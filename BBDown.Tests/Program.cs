using System.Net;
using System.Text;
using BBDown.Core;
using BBDown.Core.Util;

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

static async Task Throws(Func<Task> action)
{
    try { await action(); }
    catch (Exception) { return; }
    throw new Exception("Expected failure");
}

Config.WBI = BilibiliWebUtil.MixinKey(
    "https://i0.hdslb.com/bfs/wbi/7cd084941338484aae1ad9425b84077c.png",
    "https://i0.hdslb.com/bfs/wbi/4932caff0ff746eab6f01bf08b70ac45.png");
Check(Config.WBI == "ea1db124af3c7062474693fa704f4ff8", "Official mixin vector");
Check(Parser.WbiSign("foo=114&bar=514&zab=1919810&wts=1702204169") ==
    "bar=514&foo=114&wts=1702204169&zab=1919810&w_rid=8f6f2b5b3d485fe1886cec6a0be8c5d4", "Official signature vector");
Check(Parser.WbiSign("keyword=%E4%B8%AD%E6%96%87+%21%27%28%29%2A&wts=1702204169") ==
    Parser.WbiSign("keyword=%E4%B8%AD%E6%96%87%20&wts=1702204169"), "Unicode, space and filtered punctuation");
Check(Parser.WbiSign("foo=1&wts=1702204169&w_rid=stale") == Parser.WbiSign("wts=1702204169&foo=1"), "Stale signature removal");
await Throws(() => Task.FromResult(Parser.WbiSign("foo=1&foo=2")));
string first = BilibiliCredentialRefresher.CorrespondPath(1684466082562);
string second = BilibiliCredentialRefresher.CorrespondPath(1684466082562);
Check(first.Length == 256 && first.All(Uri.IsHexDigit) && first != second, "RSA OAEP randomized ciphertext");

var original = new BilibiliWebCredential("DedeUserID=123;DedeUserID__ckMd5=old;SESSDATA=old;bili_jct=old;buvid3=device", "old-refresh");
var saves = new List<BilibiliWebCredential>();
var handler = new RefreshHandler(saves);
using var client = new HttpClient(handler);
var rotated = await BilibiliCredentialRefresher.RefreshAsync(client, original, c => { saves.Add(c); return Task.CompletedTask; });
Check(rotated.RefreshToken == "new-refresh" && rotated.Cookie.Contains("SESSDATA=new%2Cvalue"), "Rotated credentials");
Check(rotated.Cookie.Contains("buvid3=device"), "Preserve device cookies");
Check(saves.Count == 2 && saves[0].PendingConfirmationToken == "old-refresh" && saves[1].PendingConfirmationToken == null,
    "Durable new generation before old-token confirmation");
Check(handler.Confirmed, "Confirmation sent");

foreach (string failure in new[] { "account", "cookies", "nav", "persist" })
{
    var persisted = new List<BilibiliWebCredential>();
    var broken = new RefreshHandler(persisted) { Failure = failure };
    using var http = new HttpClient(broken);
    await Throws(() => BilibiliCredentialRefresher.RefreshAsync(http, original, c =>
    {
        if (failure == "persist") throw new IOException("disk full");
        persisted.Add(c); return Task.CompletedTask;
    }));
    Check(persisted.Count == 0 && !broken.Confirmed, "Never invalidate old credentials on " + failure);
}

var pendingSaves = new List<BilibiliWebCredential>();
var interrupted = new RefreshHandler(pendingSaves) { Failure = "confirm" };
using (var http = new HttpClient(interrupted))
    await Throws(() => BilibiliCredentialRefresher.RefreshAsync(http, original, c => { pendingSaves.Add(c); return Task.CompletedTask; }));
Check(pendingSaves.Count == 1 && pendingSaves[0].PendingConfirmationToken == "old-refresh", "Keep pending confirmation on network failure");
var resumed = new RefreshHandler(pendingSaves) { NeedsRefresh = false };
using (var http = new HttpClient(resumed))
{
    var result = await BilibiliCredentialRefresher.RefreshAsync(http, pendingSaves[0], c => { pendingSaves.Add(c); return Task.CompletedTask; });
    Check(resumed.Confirmed && result.PendingConfirmationToken == null, "Resume pending confirmation");
}
var noRefresh = new RefreshHandler([]) { NeedsRefresh = false };
using (var http = new HttpClient(noRefresh))
    Check(await BilibiliCredentialRefresher.RefreshAsync(http, original, _ => throw new Exception("Unnecessary write")) == original,
        "Keep current credentials when refresh is unnecessary");
Console.WriteLine("PASS: WBI vectors, RSA OAEP, credential rotation, identity validation, persistence failure and interrupted confirmation recovery");

Check(ProjectInfo.RepositoryUrl == "https://github.com/MOPELotus/BBDown", "Fork repository");
Check(ProjectInfo.TryGetNewerVersion("v1.6.5", new Version(1, 6, 4, 0), out _), "Newer release");
Check(!ProjectInfo.TryGetNewerVersion("1.6.4", new Version(1, 6, 4, 0), out _), "Same release");
Check(!ProjectInfo.TryGetNewerVersion("1.6.3", new Version(1, 6, 4, 0), out _), "Older release");
Check(!ProjectInfo.TryGetNewerVersion("not-a-version", new Version(1, 6, 4, 0), out _), "Non-version tag");
Console.WriteLine("PASS: Fork project identity and update version comparison");

sealed class RefreshHandler(List<BilibiliWebCredential> saves) : HttpMessageHandler
{
    public string Failure { get; init; } = "";
    public bool NeedsRefresh { get; init; } = true;
    public bool Confirmed { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string path = request.RequestUri!.AbsolutePath;
        HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (path.EndsWith("cookie/info"))
            return Json("{\"code\":0,\"data\":{\"refresh\":" + (NeedsRefresh ? "true" : "false") + ",\"timestamp\":1684466082562}}");
        if (path.StartsWith("/correspond/1/"))
            return new(HttpStatusCode.OK) { Content = new StringContent("<div id='1-name'>0123456789abcdef0123456789abcdef</div>") };
        if (path.EndsWith("cookie/refresh"))
        {
            string body = await request.Content!.ReadAsStringAsync(cancellationToken);
            if (!body.Contains("refresh_token=old-refresh") || !body.Contains("csrf=old")) throw new Exception("Refresh form");
            var response = Json("{\"code\":0,\"data\":{\"status\":0,\"refresh_token\":\"new-refresh\"}}");
            foreach (var pair in new[] { "DedeUserID=" + (Failure == "account" ? "456" : "123"), "DedeUserID__ckMd5=new", "SESSDATA=new,value", "bili_jct=new" })
                if (!(Failure == "cookies" && pair.StartsWith("SESSDATA="))) response.Headers.TryAddWithoutValidation("Set-Cookie", pair + "; Path=/; HttpOnly");
            return response;
        }
        if (path.EndsWith("/nav"))
        {
            if (!request.Headers.GetValues("Cookie").Single().Contains("SESSDATA=new%2Cvalue")) throw new Exception("Verify new Cookie");
            return Json("{\"code\":0,\"data\":{\"isLogin\":" + (Failure == "nav" ? "false" : "true") + ",\"mid\":123}}");
        }
        if (path.EndsWith("confirm/refresh"))
        {
            if (saves.Count == 0 || saves[0].RefreshToken != "new-refresh") throw new Exception("Confirm before persistence");
            if (Failure == "confirm") throw new HttpRequestException("connection lost");
            string body = await request.Content!.ReadAsStringAsync(cancellationToken);
            if (!body.Contains("csrf=new") || !body.Contains("refresh_token=old-refresh")) throw new Exception("Confirm form");
            Confirmed = true;
            return Json("{\"code\":0}");
        }
        throw new Exception("Unexpected endpoint: " + path);
    }
}
