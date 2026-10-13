using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BBDown.Core.Util;

public sealed record BilibiliWebCredential(string Cookie, string RefreshToken, string? PendingConfirmationToken = null);

/// <summary>持久化新凭据后才作废旧刷新令牌，避免网络或文件写入失败导致丢失登录态。</summary>
public static class BilibiliCredentialRefresher
{
    private const string Passport = "https://passport.bilibili.com/x/passport-login/web/";
    private static readonly string[] Required = ["DedeUserID", "DedeUserID__ckMd5", "SESSDATA", "bili_jct"];

    public static async Task<BilibiliWebCredential> RefreshAsync(HttpClient client, BilibiliWebCredential credential,
        Func<BilibiliWebCredential, Task> persist)
    {
        if (string.IsNullOrWhiteSpace(credential.RefreshToken)) return credential;
        var cookies = BilibiliWebUtil.ParseCookies(credential.Cookie);
        if (Required.Any(k => string.IsNullOrEmpty(cookies.GetValueOrDefault(k))))
            throw new InvalidOperationException("登录 Cookie 不完整，请重新扫码登录");
        if (credential.PendingConfirmationToken != null)
        {
            await ConfirmAsync(client, credential);
            credential = credential with { PendingConfirmationToken = null };
            await persist(credential);
        }
        using var info = await SendJsonAsync(client, HttpMethod.Get,
            Passport + "cookie/info?csrf=" + Uri.EscapeDataString(cookies["bili_jct"]), credential.Cookie);
        var data = info.RootElement.GetProperty("data");
        if (!data.GetProperty("refresh").GetBoolean()) return credential;

        string path = CorrespondPath(data.GetProperty("timestamp").GetInt64());
        using var request = Request(HttpMethod.Get, "https://www.bilibili.com/correspond/1/" + path, credential.Cookie);
        using var response = (await client.SendAsync(request)).EnsureSuccessStatusCode();
        string html = await response.Content.ReadAsStringAsync();
        var match = Regex.Match(html, "<div\\b[^>]*\\bid\\s*=\\s*[\"']1-name[\"'][^>]*>\\s*([a-fA-F0-9]{32})\\s*</div>");
        if (!match.Success) throw new InvalidOperationException("无法获取 Cookie 续期校验值");
        using var rotateRequest = Request(HttpMethod.Post, Passport + "cookie/refresh", credential.Cookie);
        rotateRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["csrf"] = cookies["bili_jct"], ["refresh_csrf"] = match.Groups[1].Value,
            ["source"] = "main_web", ["refresh_token"] = credential.RefreshToken
        });
        using var rotateResponse = (await client.SendAsync(rotateRequest)).EnsureSuccessStatusCode();
        using var rotated = JsonDocument.Parse(await rotateResponse.Content.ReadAsStringAsync());
        RequireSuccess(rotated.RootElement);
        var rotatedData = rotated.RootElement.GetProperty("data");
        if (rotatedData.GetProperty("status").GetInt32() != 0)
            throw new InvalidOperationException("Cookie 续期未成功，请重新扫码登录");
        var updated = new Dictionary<string, string>(StringComparer.Ordinal);
        if (rotateResponse.Headers.TryGetValues("Set-Cookie", out var headers))
            foreach (string header in headers)
                foreach (var pair in BilibiliWebUtil.ParseCookies(header.Split(';', 2)[0])) updated[pair.Key] = pair.Value;
        if (Required.Any(k => string.IsNullOrEmpty(updated.GetValueOrDefault(k))) || updated["DedeUserID"] != cookies["DedeUserID"])
            throw new InvalidOperationException("续期响应的 Cookie 不完整或账号不一致，保留原凭据");
        // 保留手动提供的设备等 Cookie，仅替换这次响应中的账号凭据。
        foreach (var pair in updated) cookies[pair.Key] = pair.Value.Replace(",", "%2C");
        string cookie = string.Join(";", cookies.Select(p => p.Key + "=" + p.Value));
        string token = rotatedData.GetProperty("refresh_token").GetString() ?? "";
        if (string.IsNullOrWhiteSpace(token)) throw new InvalidOperationException("续期响应缺少刷新令牌");
        var next = new BilibiliWebCredential(cookie, token, credential.RefreshToken);
        using var nav = await SendJsonAsync(client, HttpMethod.Get, "https://api.bilibili.com/x/web-interface/nav", cookie);
        var account = nav.RootElement.GetProperty("data");
        if (!account.GetProperty("isLogin").GetBoolean() || account.GetProperty("mid").ToString() != cookies["DedeUserID"])
            throw new InvalidOperationException("续期后账号校验失败，保留原凭据");
        await persist(next);
        await ConfirmAsync(client, next);
        next = next with { PendingConfirmationToken = null };
        await persist(next);
        return next;
    }

    public static string CorrespondPath(long timestamp)
    {
        if (timestamp <= 0) throw new ArgumentOutOfRangeException(nameof(timestamp));
        const string modulus = "y4HdjgJHBlbaBN04VERG4qNBIFHP6a3GozCl75AihQloSWCXC5HDNgyinEnhaQ_4-gaMud_GF50elYXLlCToR9se9Z8z433U3KjM-3Yx7ptKkmQNAMggQwAVKgq3zYAoidNEWuxpkY_mAitTSRLnsJW-NCTa0bqBFF6Wm1MxgfE";
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Convert.FromBase64String(modulus.Replace('-', '+').Replace('_', '/') + "="),
            Exponent = [1, 0, 1]
        });
        return Convert.ToHexStringLower(rsa.Encrypt(Encoding.UTF8.GetBytes("refresh_" + timestamp), RSAEncryptionPadding.OaepSHA256));
    }

    private static HttpRequestMessage Request(HttpMethod method, string url, string cookie)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Cookie", cookie);
        request.Headers.TryAddWithoutValidation("User-Agent", HTTPUtil.UserAgent);
        request.Headers.TryAddWithoutValidation("Referer", "https://www.bilibili.com/");
        return request;
    }

    private static async Task<JsonDocument> SendJsonAsync(HttpClient client, HttpMethod method, string url, string cookie,
        Dictionary<string, string>? form = null)
    {
        using var request = Request(method, url, cookie);
        if (form != null) request.Content = new FormUrlEncodedContent(form);
        using var response = (await client.SendAsync(request)).EnsureSuccessStatusCode();
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        try { RequireSuccess(json.RootElement); return json; }
        catch { json.Dispose(); throw; }
    }

    private static async Task ConfirmAsync(HttpClient client, BilibiliWebCredential credential)
    {
        using var json = await SendJsonAsync(client, HttpMethod.Post, Passport + "confirm/refresh", credential.Cookie,
            new Dictionary<string, string>
            {
                ["csrf"] = BilibiliWebUtil.ParseCookies(credential.Cookie)["bili_jct"],
                ["refresh_token"] = credential.PendingConfirmationToken!
            });
    }

    private static void RequireSuccess(JsonElement root)
    {
        int code = root.GetProperty("code").GetInt32();
        if (code != 0) throw new InvalidOperationException($"登录续期接口返回 code={code}，请检查登录态或重新扫码");
    }
}
