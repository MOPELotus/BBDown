using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BBDown.Core.Util;

/// <summary>Web 设备身份、票据和 WBI 密钥缓存；账号 Cookie 仍由调用方提供。</summary>
public static class BilibiliWebUtil
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static string deviceCookie = "";
    private static string ticket = "";
    private static string ticketAccount = "";
    private static DateTimeOffset ticketExpires;
    private static DateTimeOffset keysExpires;
    private static DateTimeOffset deviceRetryAt;
    private static DateTimeOffset ticketRetryAt;

    public static string CookieHeader(string accountCookie)
    {
        // 手动提供的设备 Cookie 优先，避免同名 Cookie 冲突。
        var cookies = ParseCookies(deviceCookie);
        if (!string.IsNullOrEmpty(ticket) && ticketAccount == accountCookie && ticketExpires > DateTimeOffset.UtcNow)
            cookies["bili_ticket"] = ticket;
        foreach (var pair in ParseCookies(accountCookie)) cookies[pair.Key] = pair.Value;
        return string.Join("; ", cookies.Select(p => p.Key + "=" + p.Value));
    }

    public static Dictionary<string, string> ParseCookies(string value)
    {
        var cookies = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string pair in value.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Trim().Split('=', 2);
            if (parts.Length == 2) cookies[parts[0]] = parts[1];
        }
        return cookies;
    }

    public static string MixinKey(string imageUrl, string subUrl)
    {
        static string Key(string url) => Path.GetFileNameWithoutExtension(new Uri(url).AbsolutePath);
        string raw = Key(imageUrl) + Key(subUrl);
        if (raw.Length != 64 || raw.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("B站返回了无效的 WBI 密钥");
        int[] order = [46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35,
            27, 43, 5, 49, 33, 9, 42, 19, 29, 28, 14, 39, 12, 38, 41, 13];
        return string.Concat(order.Select(i => raw[i]));
    }

    public static async Task EnsureInitializedAsync()
    {
        await Gate.WaitAsync();
        try
        {
            var now = DateTimeOffset.UtcNow;
            if (deviceCookie == "" && now >= deviceRetryAt)
            {
                deviceRetryAt = now.AddMinutes(5);
                try
                {
                    using var json = JsonDocument.Parse(await HTTPUtil.GetWebSourceAsync("https://api.bilibili.com/x/frontend/finger/spi"));
                    var data = json.RootElement.GetProperty("data");
                    string buvid3 = data.GetProperty("b_3").GetString() ?? "";
                    string buvid4 = data.GetProperty("b_4").GetString() ?? "";
                    if (buvid3 == "" || buvid4 == "") throw new InvalidOperationException("设备身份为空");
                    deviceCookie = $"buvid3={buvid3}; buvid4={buvid4}";
                    using var request = new HttpRequestMessage(HttpMethod.Head, "https://www.bilibili.com/");
                    request.Headers.TryAddWithoutValidation("User-Agent", HTTPUtil.UserAgent);
                    request.Headers.TryAddWithoutValidation("Cookie", deviceCookie);
                    using var response = await HTTPUtil.AppHttpClient.SendAsync(request);
                    if (response.Headers.TryGetValues("Set-Cookie", out var headers))
                    {
                        var nut = headers.Select(h => h.Split(';', 2)[0]).FirstOrDefault(h => h.StartsWith("b_nut="));
                        if (nut != null) deviceCookie += "; " + nut;
                    }
                }
                catch (Exception) { Logger.LogDebug("设备身份获取失败，继续使用现有 Cookie"); }
            }
            if (ticketAccount != Config.COOKIE)
            {
                ticket = "";
                ticketRetryAt = DateTimeOffset.MinValue;
                ticketAccount = Config.COOKIE;
            }
            if (ticketExpires <= now.AddMinutes(5) && now >= ticketRetryAt)
            {
                ticketRetryAt = now.AddMinutes(5);
                try
                {
                    string ts = now.ToUnixTimeSeconds().ToString();
                    string signature = Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes("XgwSnGZ1p"), Encoding.UTF8.GetBytes("ts" + ts)));
                    string csrf = ParseCookies(Config.COOKIE).GetValueOrDefault("bili_jct", "");
                    using var request = new HttpRequestMessage(HttpMethod.Post,
                        $"https://api.bilibili.com/bapis/bilibili.api.ticket.v1.Ticket/GenWebTicket?key_id=ec02&hexsign={signature}&context%5Bts%5D={ts}&csrf={Uri.EscapeDataString(csrf)}");
                    request.Headers.TryAddWithoutValidation("User-Agent", HTTPUtil.UserAgent);
                    request.Headers.TryAddWithoutValidation("Referer", "https://www.bilibili.com/");
                    request.Headers.TryAddWithoutValidation("Cookie", CookieHeader(Config.COOKIE));
                    using var response = (await HTTPUtil.AppHttpClient.SendAsync(request)).EnsureSuccessStatusCode();
                    using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    var data = json.RootElement.GetProperty("data");
                    string value = data.GetProperty("ticket").GetString() ?? "";
                    if (value == "") throw new InvalidOperationException("Web 票据为空");
                    var nav = data.GetProperty("nav");
                    Config.WBI = MixinKey(nav.GetProperty("img").GetString()!, nav.GetProperty("sub").GetString()!);
                    keysExpires = now.AddHours(12);
                    ticket = value;
                    ticketExpires = now.AddSeconds(data.GetProperty("ttl").GetInt64());
                }
                catch (Exception) { Logger.LogDebug("Web 票据获取失败，使用 nav 获取 WBI 密钥"); }
            }
            if (Config.WBI.Length != 32 || keysExpires <= now)
            {
                using var json = JsonDocument.Parse(await HTTPUtil.GetWebSourceAsync("https://api.bilibili.com/x/web-interface/nav"));
                var images = json.RootElement.GetProperty("data").GetProperty("wbi_img");
                Config.WBI = MixinKey(images.GetProperty("img_url").GetString()!, images.GetProperty("sub_url").GetString()!);
                keysExpires = now.AddHours(12);
            }
        }
        finally { Gate.Release(); }
    }
}
