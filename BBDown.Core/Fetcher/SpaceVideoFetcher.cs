using BBDown.Core.Entity;
using System.Text.Json;
using static BBDown.Core.Util.HTTPUtil;
using static BBDown.Core.Logger;

namespace BBDown.Core.Fetcher;

public class SpaceVideoFetcher : IFetcher
{
    public async Task<VInfo> FetchAsync(string id)
    {
        id = id[4..];
        // using the live API can bypass w_rid
        string userInfoApi = $"https://api.live.bilibili.com/live_user/v1/Master/info?uid={id}";
        string userName = GetValidFileName(JsonDocument.Parse(await GetWebSourceAsync(userInfoApi)).RootElement.GetProperty("data").GetProperty("info").GetProperty("uname").ToString(), ".", true);
        List<string> urls = new();
        int pageSize = 30;
        int pageNumber = 1;
        using var infoJson = await GetPageAsync(pageNumber, pageSize, id);
        var pages = infoJson.RootElement.GetProperty("data").GetProperty("list").GetProperty("vlist").EnumerateArray();
        foreach (var page in pages)
        {
            urls.Add($"https://www.bilibili.com/video/av{page.GetProperty("aid")}");
        }
        int totalCount = infoJson.RootElement.GetProperty("data").GetProperty("page").GetProperty("count").GetInt32();
        int totalPage = (int)Math.Ceiling((double)totalCount / pageSize);
        while (pageNumber < totalPage)
        {
            pageNumber++;
            urls.AddRange(await GetVideosByPageAsync(pageNumber, pageSize, id));
        }
        if (urls.Count != totalCount || urls.Distinct(StringComparer.Ordinal).Count() != urls.Count)
            throw new InvalidOperationException("投稿列表分页数量发生变化，请稍后重试；未导出不完整列表");
        string path = Path.GetFullPath($"{userName}的投稿视频.txt");
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllTextAsync(temporary, string.Join(Environment.NewLine, urls));
            File.Move(temporary, path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        Log($"已导出 {urls.Count} 条投稿地址: {path}，可逐行调用 BBDown 下载");
        return new VInfo
        {
            Title = userName + "的投稿视频", Desc = "个人空间投稿地址列表", Pic = "", PubTime = 0,
            PagesInfo = [], ExportedVideoListPath = path
        };
    }

    static async Task<List<string>> GetVideosByPageAsync(int pageNumber, int pageSize, string mid)
    {
        List<string> urls = new();
        using var infoJson = await GetPageAsync(pageNumber, pageSize, mid);
        var pages = infoJson.RootElement.GetProperty("data").GetProperty("list").GetProperty("vlist").EnumerateArray();
        foreach (var page in pages)
        {
            urls.Add($"https://www.bilibili.com/video/av{page.GetProperty("aid")}");
        }
        return urls;
    }

    private static async Task<JsonDocument> GetPageAsync(int pageNumber, int pageSize, string mid)
    {
        string json;
        try
        {
            json = await GetSignedWebSourceAsync("https://api.bilibili.com/x/space/wbi/arc/search",
                $"mid={mid}&order=pubdate&pn={pageNumber}&ps={pageSize}&tid=0&web_location=333.999",
                $"https://space.bilibili.com/{mid}/upload/video");
        }
        catch (HttpRequestException e) when (e.StatusCode is System.Net.HttpStatusCode.PreconditionFailed or System.Net.HttpStatusCode.Forbidden)
        {
            throw new InvalidOperationException($"个人空间投稿列表被B站风控拦截(HTTP {(int)e.StatusCode})，请稍后重试或使用有效登录 Cookie；未导出不完整列表", e);
        }
        var document = JsonDocument.Parse(json);
        int code = document.RootElement.GetProperty("code").GetInt32();
        if (code != 0)
        {
            document.Dispose();
            throw new InvalidOperationException(code is -352 or -412
                ? $"个人空间投稿列表被B站风控拦截(code={code})，请稍后重试或在浏览器验证后使用有效 Cookie；未导出不完整列表"
                : $"获取个人空间投稿列表失败(code={code})");
        }
        return document;
    }

    private static string GetValidFileName(string input, string re = ".", bool filterSlash = false)
    {
        string title = input;
        foreach (char invalidChar in Path.GetInvalidFileNameChars())
        {
            title = title.Replace(invalidChar.ToString(), re);
        }
        if (filterSlash)
        {
            title = title.Replace("/", re);
            title = title.Replace("\\", re);
        }
        return title;
    }
}
