use std::time::Instant;

/// Git Store — Immutable append-only backup for .tza snapshots.
///
/// Every snapshot gets committed to a local git repository:
///   - Append-only: no force-push, no rebase, no amend
///   - Each commit = one .tza file + TIBET provenance token
///   - Branches per intent: `snap/code_execute`, `snap/http_get`, etc.
///   - Tags for checkpoints: `checkpoint/seq-42`, `checkpoint/daily-20260413`
///
/// Why git?
///   1. Built-in integrity: SHA-1/SHA-256 content-addressable storage
///   2. Distributed: push to remote for off-site backup
///   3. History: `git log` = full recovery timeline
///   4. Diff: `git diff` between snapshots = what changed
///   5. Bisect: `git bisect` to find when state diverged
///
/// In production: calls `git2` (libgit2 Rust bindings)
/// In simulation: tracks commits in-memory
///
/// "Git als immutable store" — Architecture Plan

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// A git commit representing a stored snapshot.
#[derive(Debug, Clone)]
pub struct GitCommit {
    /// Simulated git hash (SHA-1 of content)
    pub hash: String,
    /// Short hash (first 8 chars)
    pub short_hash: String,
    /// Commit message
    pub message: String,
    /// Branch name
    pub branch: String,
    /// File path within the repo
    pub file_path: String,
    /// Bytes written
    pub file_size: usize,
    /// Timestamp
    pub committed_at: String,
    /// Whether this commit has been pushed to remote
    pub pushed: bool,
}

/// Result of a git store operation.
#[derive(Debug, Clone)]
pub enum GitStoreResult {
    /// Committed successfully
    Committed {
        commit: GitCommit,
        commit_us: u64,
    },
    /// Committed and pushed to remote
    CommittedAndPushed {
        commit: GitCommit,
        push_us: u64,
        total_us: u64,
    },
    /// Git store is disabled
    Disabled,
    /// Failed
    Failed { reason: String },
}

/// Result of a git recovery search.
#[derive(Debug, Clone)]
pub enum GitSearchResult {
    /// Found matching commit(s)
    Found {
        commits: Vec<GitCommit>,
        search_us: u64,
    },
    /// No matching commits
    NotFound { intent: String },
    /// Git store unavailable
    Unavailable,
}

// ═══════════════════════════════════════════════════════════════
// Git Store Engine
// ═══════════════════════════════════════════════════════════════

pub struct GitStore {
    /// Path to the git repository
    pub repo_path: String,
    /// Remote URL (for push)
    pub remote_url: Option<String>,
    /// Whether to auto-push after each commit
    pub auto_push: bool,
    /// All commits (in-memory for simulation)
    commits: Vec<GitCommit>,
    /// Commit counter (for hash generation)
    commit_counter: u64,
    /// Whether the store is initialized
    pub initialized: bool,
}

impl GitStore {
    /// Create a new git store.
    ///
    /// In production: `git2::Repository::init(repo_path)` or `open(repo_path)`
    pub fn new(repo_path: &str, remote_url: Option<&str>, auto_push: bool) -> Self {
        Self {
            repo_path: repo_path.to_string(),
            remote_url: remote_url.map(|s| s.to_string()),
            auto_push,
            commits: Vec::new(),
            commit_counter: 0,
            initialized: true,
        }
    }

    /// Commit a snapshot to the git store.
    ///
    /// In production:
    ///   let repo = git2::Repository::open(&self.repo_path)?;
    ///   let branch = format!("snap/{}", intent.replace(':', "_"));
    ///   // checkout or create branch
    ///   // write .tza file
    ///   // git add + commit
    pub fn commit_snapshot(
        &mut self,
        snapshot: &crate::snapshot::Snapshot,
        tibet_token_id: &str,
    ) -> GitStoreResult {
        if !self.initialized {
            return GitStoreResult::Disabled;
        }

        let t0 = Instant::now();

        // Build branch name from intent
        let branch = format!("snap/{}", snapshot.intent.replace(':', "_"));

        // Build file path: {intent_dir}/{snapshot_id}.tza
        let file_path = format!("{}/{}.tza",
            snapshot.intent.replace(':', "/"),
            snapshot.id);

        // Generate commit hash (simulated)
        self.commit_counter += 1;
        let hash = simulate_git_hash(&snapshot.id, self.commit_counter);
        let short_hash = hash[..8].to_string();

        // Build commit message
        let message = format!(
            "snap({}): seq={} raw={}B compressed={}B ratio={:.1}x\n\n\
             TIBET: {}\n\
             Agent: {}\n\
             Content-Hash: {}\n\
             Compressed-Hash: {}",
            snapshot.intent,
            snapshot.bus_seq,
            snapshot.raw_size,
            snapshot.compressed_size,
            1.0 / snapshot.compression_ratio,
            tibet_token_id,
            snapshot.from_aint,
            snapshot.content_hash,
            snapshot.compressed_hash,
        );

        let commit = GitCommit {
            hash: hash.clone(),
            short_hash,
            message,
            branch,
            file_path,
            file_size: snapshot.compressed_size + crate::snapshot::TZA_HEADER_SIZE,
            committed_at: chrono::Utc::now().to_rfc3339(),
            pushed: false,
        };

        let commit_us = t0.elapsed().as_micros() as u64;

        // Auto-push if enabled
        if self.auto_push && self.remote_url.is_some() {
            // In production: repo.find_remote("origin")?.push(&[&refspec], None)?;
            // Simulate: ~50ms for small push over LAN
            let push_us = 50_000; // 50ms simulated
            let mut pushed_commit = commit.clone();
            pushed_commit.pushed = true;
            self.commits.push(pushed_commit.clone());

            let total_us = commit_us + push_us;
            return GitStoreResult::CommittedAndPushed {
                commit: pushed_commit,
                push_us,
                total_us,
            };
        }

        self.commits.push(commit.clone());
        GitStoreResult::Committed { commit, commit_us }
    }

    /// Tag a specific commit as a checkpoint.
    ///
    /// In production: `repo.tag(&tag_name, &commit_obj, &sig, &msg, false)?`
    pub fn tag_checkpoint(&mut self, commit_hash: &str, tag: &str) -> bool {
        if let Some(commit) = self.commits.iter().find(|c| c.hash == commit_hash) {
            // In production: creates a git tag
            println!("◈ [GitStore] Tag '{}' → {}", tag, commit.short_hash);
            true
        } else {
            false
        }
    }

    /// Search for snapshots by intent.
    ///
    /// In production:
    ///   `git log --oneline -- '{intent}/**/*.tza'`
    pub fn search_by_intent(&self, intent: &str) -> GitSearchResult {
        let t0 = Instant::now();

        let matching: Vec<_> = self.commits.iter()
            .filter(|c| c.branch.contains(&intent.replace(':', "_"))
                || c.file_path.starts_with(&intent.replace(':', "/")))
            .cloned()
            .collect();

        let search_us = t0.elapsed().as_micros() as u64;

        if matching.is_empty() {
            GitSearchResult::NotFound { intent: intent.to_string() }
        } else {
            GitSearchResult::Found {
                commits: matching,
                search_us,
            }
        }
    }

    /// Search for the most recent snapshot that can be restored.
    ///
    /// In production:
    ///   `git log -1 --format='%H' -- '{intent}/**/*.tza'`
    ///   Then: `git show {hash}:{path} > /tmp/restore.tza`
    pub fn find_latest(&self, intent: &str) -> Option<&GitCommit> {
        self.commits.iter()
            .filter(|c| c.branch.contains(&intent.replace(':', "_")))
            .last() // Newest (appended last)
    }

    /// List all branches (one per intent that has snapshots).
    pub fn list_branches(&self) -> Vec<String> {
        let mut branches: Vec<String> = self.commits.iter()
            .map(|c| c.branch.clone())
            .collect();
        branches.sort();
        branches.dedup();
        branches
    }

    /// Total commits.
    pub fn total_commits(&self) -> usize {
        self.commits.len()
    }

    /// Total bytes stored (sum of all committed .tza files).
    pub fn total_bytes(&self) -> usize {
        self.commits.iter().map(|c| c.file_size).sum()
    }

    /// Commits not yet pushed.
    pub fn unpushed_count(&self) -> usize {
        self.commits.iter().filter(|c| !c.pushed).count()
    }

    /// Store stats.
    pub fn stats(&self) -> GitStoreStats {
        GitStoreStats {
            total_commits: self.total_commits(),
            total_bytes: self.total_bytes(),
            branches: self.list_branches().len(),
            unpushed: self.unpushed_count(),
            auto_push: self.auto_push,
            has_remote: self.remote_url.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GitStoreStats {
    pub total_commits: usize,
    pub total_bytes: usize,
    pub branches: usize,
    pub unpushed: usize,
    pub auto_push: bool,
    pub has_remote: bool,
}

/// Simulate a git-style SHA-1 hash.
fn simulate_git_hash(content: &str, counter: u64) -> String {
    let mut hash: u64 = 0x6c62272e07bb0142;
    for byte in content.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= counter;
    format!("{:016x}{:016x}{:08x}",
        hash,
        hash.rotate_left(32),
        (hash >> 16) as u32)
}
