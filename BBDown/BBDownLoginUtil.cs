using QRCoder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using static BBDown.BBDownUtil;
using static BBDown.Core.Logger;
using System.Text;
using System.Text.Json;
using System.Net.Http;
using BBDown.Core.Util;

namespace BBDown;

internal static class BBDownLoginUtil
{
    private static readonly SemaphoreSlim RefreshGate = new(1, 1);
    private static string checkedCookie = "";
    private static DateTimeOffset nextRefreshCheck;
    private static string SessionPath => Path.Combine(Program.APP_DIR, "BBDown.session.json");

    internal static BilibiliWebCredential? LoadSavedLogin()
    {
        if (!File.Exists(SessionPath)) return null;
        try { return JsonSerializer.Deserialize(File.ReadAllText(SessionPath), BilibiliCredentialJsonContext.Default.BilibiliWebCredential); }
        catch (Exception) { LogWarn("本地续期凭据无法读取，尝试使用 BBDown.data"); return null; }
    }

    internal static async Task SaveLoginAsync(BilibiliWebCredential credential)
    {
        string temporary = SessionPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(credential, BilibiliCredentialJsonContext.Default.BilibiliWebCredential));
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temporary, SessionPath, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        // JSON 是续期凭据的原子存储；保留纯 Cookie 文件以兼容旧版本。
        try
        {
            await File.WriteAllTextAsync(Path.Combine(Program.APP_DIR, "BBDown.data"), credential.Cookie);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Path.Combine(Program.APP_DIR, "BBDown.data"), UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { LogWarn("已保存登录态，但未能更新旧版 BBDown.data"); }
    }

    internal static async Task RefreshSavedLoginAsync()
    {
        await RefreshGate.WaitAsync();
        try
        {
            var saved = LoadSavedLogin();
            if (saved == null || saved.Cookie != Core.Config.COOKIE || string.IsNullOrWhiteSpace(saved.RefreshToken)) return;
            if (checkedCookie == saved.Cookie && nextRefreshCheck > DateTimeOffset.UtcNow) return;
            checkedCookie = saved.Cookie;
            nextRefreshCheck = DateTimeOffset.UtcNow.AddMinutes(5);
            var refreshed = await BilibiliCredentialRefresher.RefreshAsync(HTTPUtil.AppHttpClient, saved, async credential =>
            {
                await SaveLoginAsync(credential);
                Core.Config.COOKIE = credential.Cookie;
            });
            Core.Config.COOKIE = refreshed.Cookie;
            checkedCookie = refreshed.Cookie;
            nextRefreshCheck = DateTimeOffset.UtcNow.AddHours(1);
            if (saved.Cookie != refreshed.Cookie) Log("已自动续期 WEB 登录态");
        }
        catch (Exception) { LogWarn("自动续期未完成，继续使用已保存的登录态；必要时重新扫码登录"); }
        finally { RefreshGate.Release(); }
    }
    private static readonly string[] WebLoginCookieNames =
    [
        "DedeUserID",
        "DedeUserID__ckMd5",
        "SESSDATA",
        "bili_jct",
        "sid"
    ];

    public static async Task<(string Body, string[] SetCookieHeaders)> GetLoginStatusAsync(string qrcodeKey)
    {
        string queryUrl = $"https://passport.bilibili.com/x/passport-login/web/qrcode/poll?qrcode_key={qrcodeKey}&source=main-fe-header";
        using var webRequest = new HttpRequestMessage(HttpMethod.Get, queryUrl);
        webRequest.Headers.TryAddWithoutValidation("User-Agent", HTTPUtil.UserAgent);
        webRequest.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate");
        webRequest.Headers.CacheControl = new() { NoCache = true };
        webRequest.Headers.Connection.Clear();

        using var webResponse = (await HTTPUtil.AppHttpClient.SendAsync(
            webRequest,
            HttpCompletionOption.ResponseHeadersRead)).EnsureSuccessStatusCode();

        string body = await webResponse.Content.ReadAsStringAsync();
        string[] setCookieHeaders = webResponse.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.ToArray()
            : [];

        return (body, setCookieHeaders);
    }

    private static Dictionary<string, string> GetWebLoginCookies(
        IEnumerable<string> setCookieHeaders,
        string confirmationUrl)
    {
        var cookies = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (string header in setCookieHeaders)
        {
            string pair = header.Split(';', 2)[0];
            int separatorIndex = pair.IndexOf('=');
            if (separatorIndex <= 0)
                continue;

            string name = pair[..separatorIndex].Trim();
            string value = pair[(separatorIndex + 1)..].Trim();

            if (WebLoginCookieNames.Contains(name, StringComparer.Ordinal) && !string.IsNullOrEmpty(value))
                cookies[name] = value;
        }

        // 兼容旧版行为：部分响应会把 Cookie 同时放在 data.url 查询参数中。
        if (!string.IsNullOrWhiteSpace(confirmationUrl))
        {
            foreach (string name in WebLoginCookieNames)
            {
                if (cookies.ContainsKey(name))
                    continue;

                string value = GetQueryString(name, confirmationUrl);
                if (!string.IsNullOrEmpty(value))
                    cookies[name] = value;
            }
        }

        return cookies;
    }

    private static string BuildWebLoginCookie(Dictionary<string, string> cookies)
    {
        string[] requiredCookies =
        [
            "DedeUserID",
            "DedeUserID__ckMd5",
            "SESSDATA",
            "bili_jct"
        ];

        string[] missingCookies = requiredCookies
            .Where(name => !cookies.TryGetValue(name, out string? value) || string.IsNullOrEmpty(value))
            .ToArray();

        if (missingCookies.Length > 0)
            throw new InvalidOperationException(
                $"登录成功但未获取到完整 Cookie，缺少: {string.Join(", ", missingCookies)}");

        return string.Join(
            ";",
            WebLoginCookieNames
                .Where(cookies.ContainsKey)
                .Select(name => $"{name}={cookies[name].Replace(",", "%2C")}"));
    }

    public static async Task LoginWEB()
    {
        try
        {
            Log("获取登录地址...");
            string loginUrl = "https://passport.bilibili.com/x/passport-login/web/qrcode/generate?source=main-fe-header";
            string url = JsonDocument.Parse(await HTTPUtil.GetWebSourceAsync(loginUrl)).RootElement.GetProperty("data").GetProperty("url").ToString();
            string qrcodeKey = GetQueryString("qrcode_key", url);
            //Log(oauthKey);
            //Log(url);
            bool flag = false;
            Log("生成二维码...");
            QRCodeGenerator qrGenerator = new();
            QRCodeData qrCodeData = qrGenerator.CreateQrCode(url, QRCodeGenerator.ECCLevel.Q);
            PngByteQRCode pngByteCode = new(qrCodeData);
            await File.WriteAllBytesAsync("qrcode.png", pngByteCode.GetGraphic(7));
            Log("生成二维码成功: qrcode.png, 请打开并扫描, 或扫描打印的二维码");
            var consoleQRCode = new ConsoleQRCode(qrCodeData);
            consoleQRCode.GetGraphic();

            while (true)
            {
                await Task.Delay(1000);
                var loginStatus = await GetLoginStatusAsync(qrcodeKey);
                using var loginJson = JsonDocument.Parse(loginStatus.Body);
                var data = loginJson.RootElement.GetProperty("data");
                int code = data.GetProperty("code").GetInt32();

                if (code == 86038)
                {
                    LogColor("二维码已过期, 请重新执行登录指令.");
                    break;
                }
                else if (code == 86101) //等待扫码
                {
                    continue;
                }
                else if (code == 86090) //等待确认
                {
                    if (!flag)
                    {
                        Log("扫码成功, 请确认...");
                        flag = !flag;
                    }
                }
                else if (code == 0)
                {
                    string confirmationUrl = data.TryGetProperty("url", out var urlElement)
                        ? urlElement.ToString()
                        : string.Empty;
                    Dictionary<string, string> cookies =
                        GetWebLoginCookies(loginStatus.SetCookieHeaders, confirmationUrl);
                    string cookie = BuildWebLoginCookie(cookies);

                    string refreshToken = data.TryGetProperty("refresh_token", out var tokenElement) ? tokenElement.GetString() ?? "" : "";
                    await SaveLoginAsync(new BilibiliWebCredential(cookie, refreshToken));
                    Log("登录成功，已保存 WEB 凭据");
                    File.Delete("qrcode.png");
                    break;
                }
                else throw new InvalidOperationException($"登录轮询返回未知状态 code={code}");
            }
        }
        catch (Exception e) { LogError(e.Message); }
    }

    public static async Task LoginTV()
    {
        try
        {
            string loginUrl = "https://passport.snm0516.aisee.tv/x/passport-tv-login/qrcode/auth_code";
            string pollUrl = "https://passport.bilibili.com/x/passport-tv-login/qrcode/poll";
            var parms = GetTVLoginParms();
            Log("获取登录地址...");
            byte[] responseArray = await (await HTTPUtil.AppHttpClient.PostAsync(loginUrl, new FormUrlEncodedContent(parms.ToDictionary()))).Content.ReadAsByteArrayAsync();
            string web = Encoding.UTF8.GetString(responseArray);
            string url = JsonDocument.Parse(web).RootElement.GetProperty("data").GetProperty("url").ToString();
            string authCode = JsonDocument.Parse(web).RootElement.GetProperty("data").GetProperty("auth_code").ToString();
            Log("生成二维码...");
            QRCodeGenerator qrGenerator = new();
            QRCodeData qrCodeData = qrGenerator.CreateQrCode(url, QRCodeGenerator.ECCLevel.Q);
            PngByteQRCode pngByteCode = new(qrCodeData);
            await File.WriteAllBytesAsync("qrcode.png", pngByteCode.GetGraphic(7));
            Log("生成二维码成功: qrcode.png, 请打开并扫描, 或扫描打印的二维码");
            var consoleQRCode = new ConsoleQRCode(qrCodeData);
            consoleQRCode.GetGraphic();
            parms.Set("auth_code", authCode);
            parms.Set("ts", GetTimeStamp(true));
            parms.Remove("sign");
            parms.Add("sign", GetSign(ToQueryString(parms)));
            while (true)
            {
                await Task.Delay(1000);
                responseArray = await (await HTTPUtil.AppHttpClient.PostAsync(pollUrl, new FormUrlEncodedContent(parms.ToDictionary()))).Content.ReadAsByteArrayAsync();
                web = Encoding.UTF8.GetString(responseArray);
                string code = JsonDocument.Parse(web).RootElement.GetProperty("code").ToString();
                if (code == "86038")
                {
                    LogColor("二维码已过期, 请重新执行登录指令.");
                    break;
                }
                else if (code == "86039") //等待扫码
                {
                    continue;
                }
                else
                {
                    string cc = JsonDocument.Parse(web).RootElement.GetProperty("data").GetProperty("access_token").ToString();
                    Log("登录成功: AccessToken=" + cc);
                    //导出cookie
                    await File.WriteAllTextAsync(Path.Combine(Program.APP_DIR, "BBDownTV.data"), "access_token=" + cc);
                    File.Delete("qrcode.png");
                    break;
                }
            }
        }
        catch (Exception e) { LogError(e.Message); }
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(BilibiliWebCredential))]
internal partial class BilibiliCredentialJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
