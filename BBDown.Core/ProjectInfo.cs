namespace BBDown.Core;

public static class ProjectInfo
{
    public const string ForkAuthor = "MOPELotus";
    public const string UpstreamAuthor = "nilaoda";
    public const string RepositoryUrl = "https://github.com/MOPELotus/BBDown";
    public const string IssuesUrl = RepositoryUrl + "/issues";
    public const string ReleasesUrl = RepositoryUrl + "/releases";

    public static bool TryGetNewerVersion(string tag, Version installed, out Version? latest)
    {
        if (!Version.TryParse(tag.TrimStart('v', 'V'), out latest) || latest.Build < 0) return false;
        return new Version(latest.Major, latest.Minor, latest.Build) >
            new Version(installed.Major, installed.Minor, installed.Build);
    }
}
