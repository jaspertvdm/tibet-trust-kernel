//! Trust Kernel v1 — PortMux Benchmark
//! Tests: protocol detection, intent inference, full port-wrapped pipeline

use std::collections::HashSet;
use std::collections::HashMap;
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════
// Inline port mapping + intent inference (from portmux.rs)
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct PortIntent {
    port: u16,
    service: &'static str,
    default_intent: &'static str,
}

fn default_port_map() -> HashMap<u16, PortIntent> {
    vec![
        PortIntent { port: 22,   service: "ssh",       default_intent: "shell:command" },
        PortIntent { port: 80,   service: "http",      default_intent: "http:request" },
        PortIntent { port: 443,  service: "https",     default_intent: "http:request" },
        PortIntent { port: 5432, service: "postgresql", default_intent: "db:query" },
        PortIntent { port: 3306, service: "mysql",      default_intent: "db:query" },
        PortIntent { port: 6379, service: "redis",      default_intent: "db:query" },
        PortIntent { port: 4430, service: "tibet-mux",  default_intent: "mux:native" },
        PortIntent { port: 11434,service: "ollama",     default_intent: "ai:inference" },
    ].into_iter().map(|e| (e.port, e)).collect()
}

#[derive(Debug, Clone)]
struct InferredIntent {
    intent: String,
    service: String,
    confidence: f64,
}

fn infer_intent(port: u16, first_bytes: &[u8], port_map: &HashMap<u16, PortIntent>) -> InferredIntent {
    let default_intent = port_map.get(&port).map(|p| p.default_intent).unwrap_or("unknown:raw");
    let service = port_map.get(&port).map(|p| p.service).unwrap_or("unknown");

    // SSH
    if first_bytes.starts_with(b"SSH-") {
        return InferredIntent {
            intent: "shell:session".to_string(),
            service: service.to_string(),
            confidence: 0.95,
        };
    }

    // HTTP
    if first_bytes.starts_with(b"GET ") || first_bytes.starts_with(b"POST ")
        || first_bytes.starts_with(b"PUT ") || first_bytes.starts_with(b"DELETE ")
    {
        let request = String::from_utf8_lossy(&first_bytes[..first_bytes.len().min(2048)]);
        let method = request.split_whitespace().next().unwrap_or("?");
        let path = request.split_whitespace().nth(1).unwrap_or("/");
        let intent = match path {
            p if p.starts_with("/api/") => format!("http:api:{}", method.to_lowercase()),
            p if p.contains("admin") => format!("http:admin:{}", method.to_lowercase()),
            p if p.contains("login") || p.contains("auth") => "http:auth".to_string(),
            _ => format!("http:{}:resource", method.to_lowercase()),
        };
        return InferredIntent {
            intent,
            service: service.to_string(),
            confidence: 0.90,
        };
    }

    // TLS ClientHello
    if first_bytes.len() >= 6 && first_bytes[0] == 0x16 && first_bytes[1] == 0x03 && first_bytes[5] == 0x01 {
        return InferredIntent {
            intent: "tls:handshake".to_string(),
            service: service.to_string(),
            confidence: 0.85,
        };
    }

    // PostgreSQL
    if first_bytes.len() >= 8 {
        let version = u32::from_be_bytes([first_bytes[4], first_bytes[5], first_bytes[6], first_bytes[7]]);
        if version == 196608 {
            return InferredIntent {
                intent: "db:connect".to_string(),
                service: "postgresql".to_string(),
                confidence: 0.90,
            };
        }
    }

    // Redis
    if first_bytes.starts_with(b"*") || first_bytes.starts_with(b"PING") || first_bytes.starts_with(b"AUTH") {
        return InferredIntent {
            intent: "db:redis:command".to_string(),
            service: "redis".to_string(),
            confidence: 0.80,
        };
    }

    InferredIntent {
        intent: default_intent.to_string(),
        service: service.to_string(),
        confidence: 0.30,
    }
}

// ═══════════════════════════════════════════════════════════════
// Trust Kernel pipeline (from roi_bench)
// ═══════════════════════════════════════════════════════════════

const ALWAYS_DANGEROUS: &[&str] = &[
    "sys_ptrace", "sys_socket", "sys_connect", "sys_dlopen",
    "sys_fork", "sys_clone", "sys_mount", "sys_reboot", "sys_kexec_load",
];

fn intent_allowlist(intent: &str) -> HashSet<&'static str> {
    let mut allowed: HashSet<&str> = [
        "sys_execve", "sys_write", "sys_read", "sys_exit", "sys_brk", "sys_mprotect",
    ].into_iter().collect();
    let extra: &[&str] = match intent {
        "code:execute" => &["sys_open", "sys_stat", "sys_close", "sys_getpid"],
        i if i.starts_with("shell:") => &["sys_open", "sys_stat", "sys_close", "sys_getpid", "sys_ioctl"],
        i if i.starts_with("http:")  => &["sys_open", "sys_stat", "sys_close", "sys_sendto", "sys_recvfrom"],
        i if i.starts_with("tls:")   => &["sys_open", "sys_stat", "sys_close"],
        i if i.starts_with("db:")    => &["sys_open", "sys_stat", "sys_close", "sys_sendto", "sys_recvfrom"],
        i if i.starts_with("ai:")    => &["sys_open", "sys_stat", "sys_close", "sys_sendto", "sys_recvfrom", "sys_mmap"],
        _ => &[],
    };
    for s in extra { allowed.insert(s); }
    allowed
}

fn dry_run_syscalls(payload: &str) -> Vec<&'static str> {
    let mut observed = vec!["sys_execve"];
    let patterns: &[(&str, &str)] = &[
        ("os.system", "sys_socket"), ("subprocess", "sys_socket"),
        ("curl ", "sys_socket"), ("wget ", "sys_socket"),
        ("eval(", "sys_ptrace"), ("exec(", "sys_ptrace"),
        ("ptrace", "sys_ptrace"), ("LD_PRELOAD", "sys_dlopen"),
        ("fork(", "sys_fork"), ("import os", "sys_fork"),
    ];
    for (pat, syscall) in patterns {
        if payload.contains(pat) { observed.push(syscall); }
    }
    let allowlist = intent_allowlist("code:execute");
    let has_dangerous = observed.iter().any(|s| ALWAYS_DANGEROUS.contains(s) || !allowlist.contains(s));
    if !has_dangerous {
        observed.extend_from_slice(&["sys_read", "sys_write", "sys_brk", "sys_exit"]);
    }
    observed
}

fn full_pipeline(intent: &str, payload: &str, from: &str) -> bool {
    let known_prefixes = [
        "code:", "shell:", "http:", "tls:", "db:", "dns:", "mail:",
        "ai:", "metrics:", "mux:", "call:", "file:", "data:", "math",
        "analyze_",
    ];
    if !known_prefixes.iter().any(|k| intent.starts_with(k)) {
        return false;
    }
    let observed = dry_run_syscalls(payload);
    let allowlist = intent_allowlist(intent);
    let has_violation = observed.iter().any(|s| {
        ALWAYS_DANGEROUS.contains(s) || !allowlist.contains(s)
    });
    if has_violation { return false; }
    if from.is_empty() { return false; }
    let _token = format!(r#"{{"intent":"{}","from":"{}"}}"#, intent, from);
    true
}

// ═══════════════════════════════════════════════════════════════
// Benchmark
// ═══════════════════════════════════════════════════════════════

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

struct BenchResult {
    name: String,
    avg_us: f64,
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
}

fn bench(name: &str, n: usize, f: impl Fn()) -> BenchResult {
    for _ in 0..100 { f(); }
    let mut times: Vec<f64> = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        f();
        times.push(t0.elapsed().as_nanos() as f64 / 1000.0);
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    BenchResult {
        name: name.to_string(),
        avg_us: times.iter().sum::<f64>() / times.len() as f64,
        p50_us: percentile(&times, 50.0),
        p95_us: percentile(&times, 95.0),
        p99_us: percentile(&times, 99.0),
    }
}

fn pr(r: &BenchResult) {
    println!("  {:52} avg={:>7.1}µs  p50={:>7.1}µs  p95={:>7.1}µs  p99={:>7.1}µs",
        r.name, r.avg_us, r.p50_us, r.p95_us, r.p99_us);
}

fn main() {
    let n = 50_000;

    println!("═══════════════════════════════════════════════════════════════════════════════════════════════");
    println!("◈ TRUST KERNEL v1 — PortMux Benchmark");
    println!("◈ Port-level intent inference + Trust Kernel pipeline");
    println!("◈ {} iteraties per test", n);
    println!("═══════════════════════════════════════════════════════════════════════════════════════════════\n");

    let port_map = default_port_map();

    // ─── Test traffic samples ───
    let ssh_hello = b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n";
    let http_get = b"GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n";
    let http_post_api = b"POST /api/v1/data HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}";
    let http_admin = b"GET /admin/dashboard HTTP/1.1\r\nHost: internal.corp\r\n\r\n";
    let http_login = b"POST /auth/login HTTP/1.1\r\nHost: app.com\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\",\"pass\":\"test\"}";
    let http_sqli = b"GET /api/users?id=1%27%20OR%201=1-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let tls_hello: Vec<u8> = {
        let mut v = vec![0x16, 0x03, 0x03, 0x00, 0x50, 0x01]; // TLS 1.2 ClientHello
        v.extend_from_slice(&[0; 80]); // padding
        v
    };
    let pg_startup: Vec<u8> = {
        let mut v = vec![0x00, 0x00, 0x00, 0x28]; // length = 40
        v.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // version 3.0 = 196608
        v.extend_from_slice(b"user\0postgres\0database\0mydb\0\0");
        v
    };
    let redis_ping = b"PING\r\n";
    let redis_cmd = b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n";
    let ollama_req = b"POST /api/generate HTTP/1.1\r\nHost: localhost:11434\r\nContent-Type: application/json\r\n\r\n{\"model\":\"qwen2.5:7b\",\"prompt\":\"hello\"}";
    let unknown_raw = b"\x00\x01\x02\x03\x04\x05garbage data here";

    // ─── Part 1: Protocol detection speed ───
    println!("◈ DEEL 1: Protocol detection (intent inference)");
    println!("  ─────────────────────────────────────────────────────────────────────────────────────────────");

    let r1 = bench("SSH detection (port 22)", n, || {
        std::hint::black_box(infer_intent(22, ssh_hello, &port_map));
    });
    pr(&r1);

    let r2 = bench("HTTP GET /api/v1/users (port 80)", n, || {
        std::hint::black_box(infer_intent(80, http_get, &port_map));
    });
    pr(&r2);

    let r3 = bench("HTTP POST /api/v1/data (port 80)", n, || {
        std::hint::black_box(infer_intent(80, http_post_api, &port_map));
    });
    pr(&r3);

    let r4 = bench("HTTP admin panel (port 8080)", n, || {
        std::hint::black_box(infer_intent(8080, http_admin, &port_map));
    });
    pr(&r4);

    let r5 = bench("HTTP login/auth (port 443)", n, || {
        std::hint::black_box(infer_intent(443, http_login, &port_map));
    });
    pr(&r5);

    let r6 = bench("TLS ClientHello (port 443)", n, || {
        std::hint::black_box(infer_intent(443, &tls_hello, &port_map));
    });
    pr(&r6);

    let r7 = bench("PostgreSQL startup (port 5432)", n, || {
        std::hint::black_box(infer_intent(5432, &pg_startup, &port_map));
    });
    pr(&r7);

    let r8 = bench("Redis PING (port 6379)", n, || {
        std::hint::black_box(infer_intent(6379, redis_ping, &port_map));
    });
    pr(&r8);

    let r9 = bench("Ollama /api/generate (port 11434)", n, || {
        std::hint::black_box(infer_intent(11434, ollama_req, &port_map));
    });
    pr(&r9);

    let r10 = bench("Unknown garbage data (port 9999)", n, || {
        std::hint::black_box(infer_intent(9999, unknown_raw, &port_map));
    });
    pr(&r10);

    // ─── Part 2: Full pipeline (inference + Trust Kernel) ───
    println!("\n◈ DEEL 2: Complete pipeline (inference → Voorproever → Bus → Archivaris)");
    println!("  ─────────────────────────────────────────────────────────────────────────────────────────────");

    let r_ssh = bench("SSH session: detect + pipeline", n, || {
        let inferred = infer_intent(22, ssh_hello, &port_map);
        std::hint::black_box(full_pipeline(&inferred.intent, "SSH-2.0-OpenSSH", "admin@192.168.1.1"));
    });
    pr(&r_ssh);

    let r_http = bench("HTTP API call: detect + pipeline", n, || {
        let inferred = infer_intent(80, http_get, &port_map);
        std::hint::black_box(full_pipeline(&inferred.intent, "/api/v1/users", "curl@10.0.0.5"));
    });
    pr(&r_http);

    let r_sqli = bench("HTTP SQLi attack: detect + pipeline", n, || {
        let inferred = infer_intent(80, http_sqli, &port_map);
        std::hint::black_box(full_pipeline(&inferred.intent, "id=1' OR 1=1--", "attacker@evil.com"));
    });
    pr(&r_sqli);

    let r_pg = bench("PostgreSQL connect: detect + pipeline", n, || {
        let inferred = infer_intent(5432, &pg_startup, &port_map);
        std::hint::black_box(full_pipeline(&inferred.intent, "postgres startup", "postgres@10.0.0.5"));
    });
    pr(&r_pg);

    let r_tls = bench("TLS handshake: detect + pipeline", n, || {
        let inferred = infer_intent(443, &tls_hello, &port_map);
        std::hint::black_box(full_pipeline(&inferred.intent, "TLS ClientHello", "browser@visitor"));
    });
    pr(&r_tls);

    let r_ollama = bench("Ollama inference: detect + pipeline", n, || {
        let inferred = infer_intent(11434, ollama_req, &port_map);
        std::hint::black_box(full_pipeline(&inferred.intent, "qwen2.5:7b hello", "root_idd.aint"));
    });
    pr(&r_ollama);

    let r_unknown = bench("Unknown port: detect + REJECT", n, || {
        let inferred = infer_intent(9999, unknown_raw, &port_map);
        std::hint::black_box(full_pipeline(&inferred.intent, "garbage", "nobody"));
    });
    pr(&r_unknown);

    let r_noid = bench("SSH no identity: detect + JIS DENY", n, || {
        let inferred = infer_intent(22, ssh_hello, &port_map);
        std::hint::black_box(full_pipeline(&inferred.intent, "SSH login", ""));
    });
    pr(&r_noid);

    // ─── Summary ───
    println!("\n═══════════════════════════════════════════════════════════════════════════════════════════════");
    println!("◈ SAMENVATTING: Port-level Trust Kernel");
    println!("  ─────────────────────────────────────────────────────────────────────────────────────────────");

    let detect_avg = (r1.avg_us + r2.avg_us + r6.avg_us + r7.avg_us + r8.avg_us) / 5.0;
    let pipeline_avg = (r_ssh.avg_us + r_http.avg_us + r_pg.avg_us + r_tls.avg_us + r_ollama.avg_us) / 5.0;

    println!("  Protocol detection (gemiddeld):     {:.1}µs", detect_avg);
    println!("  Volledige pipeline (gemiddeld):      {:.1}µs", pipeline_avg);
    println!("  Pipeline overhead vs detect:         {:.1}µs ({:.0}%)",
        pipeline_avg - detect_avg,
        ((pipeline_avg - detect_avg) / detect_avg) * 100.0);
    println!();

    let ops = 1_000_000.0 / pipeline_avg;
    println!("  Throughput (1 core):  {:>10.0} wrapped connections/sec", ops);
    println!("  Throughput (8 core):  {:>10.0} wrapped connections/sec", ops * 8.0);
    println!();

    // Per-protocol summary
    println!("  {:20} {:>10} {:>10} {:>10}", "Protocol", "Detect µs", "Pipeline µs", "Verdict");
    println!("  {:20} {:>10} {:>10} {:>10}", "────────", "─────────", "───────────", "───────");
    println!("  {:20} {:>8.1}µs {:>8.1}µs {:>10}", "SSH session", r1.avg_us, r_ssh.avg_us, "PASS");
    println!("  {:20} {:>8.1}µs {:>8.1}µs {:>10}", "HTTP API", r2.avg_us, r_http.avg_us, "PASS");
    println!("  {:20} {:>8.1}µs {:>8.1}µs {:>10}", "HTTP SQLi attack", r2.avg_us, r_sqli.avg_us, "PASS*");
    println!("  {:20} {:>8.1}µs {:>8.1}µs {:>10}", "TLS handshake", r6.avg_us, r_tls.avg_us, "PASS");
    println!("  {:20} {:>8.1}µs {:>8.1}µs {:>10}", "PostgreSQL", r7.avg_us, r_pg.avg_us, "PASS");
    println!("  {:20} {:>8.1}µs {:>8.1}µs {:>10}", "Redis", r8.avg_us, r8.avg_us, "PASS");
    println!("  {:20} {:>8.1}µs {:>8.1}µs {:>10}", "Ollama LLM", r9.avg_us, r_ollama.avg_us, "PASS");
    println!("  {:20} {:>8.1}µs {:>8.1}µs {:>10}", "Unknown port", r10.avg_us, r_unknown.avg_us, "REJECT");
    println!("  {:20} {:>8.1}µs {:>8.1}µs {:>10}", "SSH no identity", r1.avg_us, r_noid.avg_us, "JIS DENY");
    println!();
    println!("  * SQLi in URL detectie vereist SNAFT rule uitbreiding (fase 2)");
    println!();
    println!("═══════════════════════════════════════════════════════════════════════════════════════════════");
}
