// Public GitHub repo scan, client-side and bounded.
// Uses only the unauthenticated public GitHub API (60 requests/hour) and
// raw.githubusercontent.com. No token, no account, no server involved.

export interface RepoFile {
  path: string;
  size: number;
}

export interface RepoScanProgress {
  stage: string;
  filesFetched: number;
  filesTotal: number;
}

const MAX_FILES = 25;
const MAX_FILE_BYTES = 200 * 1024;

const TEXT_EXTENSIONS = new Set([
  ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".env", ".txt", ".md",
  ".yaml", ".yml", ".toml", ".cfg", ".ini", ".sh", ".java", ".go", ".rb",
  ".php", ".cs", ".cpp", ".h", ".c", ".rs", ".swift", ".kt", ".xml",
  ".html", ".css", ".sql", ".tf", ".conf", ".properties", ".lock",
]);

const SKIP_BASENAMES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "composer.lock",
  "Gemfile.lock",
  "poetry.lock",
]);

export function parseRepoUrl(input: string): { owner: string; repo: string } | null {
  const trimmed = input.trim().replace(/\/$/, "");
  const m = trimmed.match(
    /^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/,
  );
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

async function githubJson<T>(url: string): Promise<T> {
  const res = await fetch(url, {
    headers: { Accept: "application/vnd.github+json" },
  });
  if (res.status === 403) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    const reset = res.headers.get("x-ratelimit-reset");
    const when = reset
      ? new Date(Number(reset) * 1000).toLocaleTimeString()
      : "soon";
    throw new Error(
      remaining === "0"
        ? `GitHub API rate limit reached (60 requests/hour without a token). It resets around ${when} — try again then.`
        : `GitHub refused the request (HTTP 403).`,
    );
  }
  if (res.status === 404) {
    throw new Error("Repository not found, or it is private.");
  }
  if (!res.ok) {
    throw new Error(`GitHub API error: HTTP ${res.status}.`);
  }
  return (await res.json()) as T;
}

function isTextFile(path: string, size: number): boolean {
  const base = path.split("/").pop() ?? "";
  if (SKIP_BASENAMES.has(base)) return false;
  if (base === ".env" || base.startsWith(".env.")) return true;
  const dot = base.lastIndexOf(".");
  if (dot === -1) return false;
  return TEXT_EXTENSIONS.has(base.slice(dot).toLowerCase());
}

/** Fetch a capped set of small text files from a public repo. */
export async function fetchRepoFiles(
  owner: string,
  repo: string,
  onProgress: (p: RepoScanProgress) => void,
): Promise<Array<{ name: string; text: string }>> {
  const meta = await githubJson<{ default_branch: string }>(
    `https://api.github.com/repos/${owner}/${repo}`,
  );
  const branch = meta.default_branch;
  const tree = await githubJson<{
    tree: Array<{ path: string; type: string; size?: number }>;
    truncated?: boolean;
  }>(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
  );

  const candidates = tree.tree
    .filter((e) => e.type === "blob" && e.size !== undefined)
    .filter((e) => isTextFile(e.path, e.size as number))
    .filter((e) => (e.size as number) <= MAX_FILE_BYTES)
    .slice(0, MAX_FILES);

  if (tree.truncated) {
    // Large repos return a truncated tree; we still scan what we got.
  }

  const files: Array<{ name: string; text: string }> = [];
  for (let i = 0; i < candidates.length; i++) {
    const entry = candidates[i];
    onProgress({
      stage: `Fetching ${entry.path}`,
      filesFetched: i,
      filesTotal: candidates.length,
    });
    try {
      const res = await fetch(
        `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${entry.path}`,
      );
      if (!res.ok) continue;
      const text = await res.text();
      files.push({ name: entry.path, text });
    } catch {
      // Skip unreadable files and keep going.
      continue;
    }
  }
  onProgress({
    stage: "Done",
    filesFetched: files.length,
    filesTotal: candidates.length,
  });
  return files;
}
