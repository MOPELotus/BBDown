using QRCoder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using static BBDown.BBDownUtil;
using static BBDown.Core.Logger;
using System.Text;
using System.Text.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using BBDown.Core.Util;

namespace BBDown;

internal static class BBDownLoginUtil
{
    private static readonly string[] WebLoginCookieNames =
    [
        "DedeUserID",
        "DedeUserID__ckMd5",
        "SESSDATA",
        "bili_jct",
        "sid"
    ];

    private static readonly string[] RequiredWebLoginCookieNames =
    [
        "DedeUserID",
        "DedeUserID__ckMd5",
        "SESSDATA",
        "bili_jct"
    ];

    public static async Task<HttpResponseMessage> GetLoginStatusAsync(string qrcodeKey)
    {
        string queryUrl = $"https://passport.bilibili.com/x/passport-login/web/qrcode/poll?qrcode_key={qrcodeKey}&source=main-fe-header";
        using var request = new HttpRequestMessage(HttpMethod.Get, queryUrl);
        request.Headers.TryAddWithoutValidation("User-Agent", HTTPUtil.UserAgent);
        request.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate");
        request.Headers.CacheControl = CacheControlHeaderValue.Parse("no-cache");
        request.Headers.Connection.Clear();

        return (await HTTPUtil.AppHttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead))
            .EnsureSuccessStatusCode();
    }

    private static Dictionary<string, string> GetWebLoginCookies(HttpResponseMessage response, string confirmationUrl)
    {
        var cookies = new Dictionary<string, string>(StringComparer.Ordinal);

        if (response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
        {
            foreach (string header in setCookieHeaders)
            {
                string pair = header.Split(';', 2)[0];
                int separatorIndex = pair.IndexOf('=');
                if (separatorIndex <= 0)
                    continue;

                string name = pair[..separatorIndex];
                string value = pair[(separatorIndex + 1)..];
                if (string.IsNullOrEmpty(value))
                    continue;

                if (name is "DedeUserID" or "DedeUserID__ckMd5" or "SESSDATA" or "bili_jct" or "sid")
                    cookies[name] = value;
            }
        }

        // 兼容旧版行为：部分响应会把登录 Cookie 放在 data.url 查询参数中。
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

        foreach (string name in RequiredWebLoginCookieNames)
        {
            if (!cookies.TryGetValue(name, out string? value) || string.IsNullOrEmpty(value))
                throw new Exception($"登录成功但响应未返回 {name}, B站登录接口可能已发生变化.");
        }

        return cookies;
    }

    private static string BuildWebLoginCookie(Dictionary<string, string> cookies)
    {
        var values = new List<string>();
        foreach (string name in WebLoginCookieNames)
        {
            if (cookies.TryGetValue(name, out string? value) && !string.IsNullOrEmpty(value))
                values.Add($"{name}={value}");
        }

        // 保持原有 BBDown.data 兼容行为：转义英文逗号。
        return string.Join(";", values).Replace(",", "%2C");
    }

    public static async Task LoginWEB()
    {
        try
        {
            Log("获取登录地址...");
            string loginUrl = "https://passport.bilibili.com/x/passport-login/web/qrcode/generate?source=main-fe-header";
            string url = JsonDocument.Parse(await HTTPUtil.GetWebSourceAsync(loginUrl)).RootElement.GetProperty("data").GetProperty("url").ToString();
            string qrcodeKey = GetQueryString("qrcode_key", url);
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
                using HttpResponseMessage loginResponse = await GetLoginStatusAsync(qrcodeKey);
                string w = await loginResponse.Content.ReadAsStringAsync();
                int code = JsonDocument.Parse(w).RootElement.GetProperty("data").GetProperty("code").GetInt32();
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
                else
                {
                    JsonElement data = JsonDocument.Parse(w).RootElement.GetProperty("data");
                    string confirmationUrl = data.TryGetProperty("url", out JsonElement urlElement)
                        ? urlElement.ToString()
                        : string.Empty;
                    Dictionary<string, string> cookies = GetWebLoginCookies(loginResponse, confirmationUrl);
                    string cookie = BuildWebLoginCookie(cookies);

                    Log("登录成功: SESSDATA=已获取");
                    await File.WriteAllTextAsync(Path.Combine(Program.APP_DIR, "BBDown.data"), cookie);
                    File.Delete("qrcode.png");
                    break;
                }
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
