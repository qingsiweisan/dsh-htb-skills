#!/usr/bin/env node
// HTB Sherlock 自动化:info / tasks / download / submit / submit-file / progress
//
// 端点 (base = https://labs.hackthebox.com, Bearer = htb-token):
//   GET  /api/v4/sherlocks/{slug}              -> {data:{id,name,difficulty,...}}
//   GET  /api/v4/sherlocks/{id}/play           -> {data:{scenario,file_name,file_size}}
//   GET  /api/v4/sherlocks/{id}/tasks          -> {data:[{id,title,description,hint,masked_flag}]}
//   GET  /api/v4/sherlocks/{id}/download_link  -> {url,expires_in} (签名重定向)
//   GET  {url}                                 -> 跟随 302 下载 zip
//   POST /api/v4/sherlocks/{id}/tasks/{tid}/flag  body {"flag":"..."} -> owned?/incorrect
//   GET  /api/v4/sherlocks/{id}/progress       -> {data:{is_owned,progress,tasks_answered,own_rank}}
//
// 认证: --token 参数 > $HTB_TOKEN 环境变量 > ~/.dsh/htb-token.txt > ./htb-token.txt
//   token 是 3 天 JWT。从浏览器拿并落盘(不转写):
//     页面上下文 fetch 里 `localStorage.getItem('htb-token')` 得到一个字符串后,
//     用 data: URL 下载成文件: 见 skills/sherlock-investigation/SKILL.md §0。
//
// zip 密码: HTB Sherlock 默认 'hacktheblue'(可用 --password 覆盖)。
//
// 用法:
//   node sherlock.mjs info <slug>                  # 元数据 + 场景 + 全部任务(含 hint)
//   node sherlock.mjs tasks <slug>                 # 只列任务 id/hint/mask
//   node sherlock.mjs download <slug> [-p PASS] [-o DIR]
//   node sherlock.mjs submit <slug> <task> <answer>   # task = 任务 id 或 1-based 序号
//   node sherlock.mjs submit-file <slug> <answers.json> # {1:"...",2:"..."} 或 {taskId:"..."}
//   node sherlock.mjs progress <slug>
//
// 依赖: 仅 Node 18+ 内置(fetch/fs/child_process),无需 npm install。

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const BASE = process.env.HTB_BASE || 'https://labs.hackthebox.com';

function usage() {
  console.error(`用法见脚本头注释。示例:
  node sherlock.mjs info Baggage
  node sherlock.mjs download Baggage -p hacktheblue -o ./work
  node sherlock.mjs submit Baggage 2 "Everything 1.4.1.1028"
  node sherlock.mjs submit-file Baggage answers.json
  node sherlock.mjs progress Baggage`);
  process.exit(2);
}

function getToken(optToken) {
  if (optToken) return optToken;
  if (process.env.HTB_TOKEN) return process.env.HTB_TOKEN;
  const candidates = [
    path.join(os.homedir(), '.dsh', 'htb-token.txt'),
    path.join(process.cwd(), 'htb-token.txt'),
  ];
  for (const f of candidates) {
    if (fs.existsSync(f)) {
      const t = fs.readFileSync(f, 'utf8').trim();
      if (t) return t;
    }
  }
  console.error('缺少 htb-token: 用 --token 传, 或设 $HTB_TOKEN, 或放到 ~/.dsh/htb-token.txt');
  process.exit(2);
}

async function api(pathname, token, opts = {}) {
  const res = await fetch(BASE + pathname, {
    headers: { authorization: 'Bearer ' + token, accept: 'application/json' },
    ...opts,
  });
  return res;
}

async function apiJson(pathname, token, opts = {}) {
  const res = await api(pathname, token, opts);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { _raw: text }; }
  if (res.status === 401) {
    console.error('401 未认证: token 过期或无效。重新登录 HTB, 用浏览器 localStorage htb-token 刷新 ~/.dsh/htb-token.txt');
    process.exit(2);
  }
  return { status: res.status, json };
}

async function resolveId(slug, token) {
  const { status, json } = await apiJson(`/api/v4/sherlocks/${encodeURIComponent(slug)}`, token);
  if (status !== 200 || !json.data) {
    console.error(`解析 sherlock '${slug}' 失败 (status ${status}): ${JSON.stringify(json)}`);
    process.exit(2);
  }
  return json.data;
}

async function getTasks(id, token) {
  const { status, json } = await apiJson(`/api/v4/sherlocks/${id}/tasks`, token);
  if (status !== 200 || !json.data) {
    console.error(`获取任务列表失败 (status ${status}): ${JSON.stringify(json)}`);
    process.exit(2);
  }
  return json.data;
}

function which(cmd) {
  try { execFileSync(cmd, ['--version'], { stdio: 'ignore' }); return true; } catch { return false; }
}

async function download(id, token, password, outDir) {
  const { status, json } = await apiJson(`/api/v4/sherlocks/${id}/download_link`, token);
  if (status !== 200 || !json.url) {
    console.error(`获取下载链接失败 (status ${status}): ${JSON.stringify(json)}`);
    process.exit(2);
  }
  const url = json.url;
  const res = await fetch(url, { headers: { authorization: 'Bearer ' + token } });
  if (!res.ok) { console.error(`下载失败: HTTP ${res.status}`); process.exit(2); }
  const buf = Buffer.from(await res.arrayBuffer());
  const zipName = 'sherlock.zip';
  fs.mkdirSync(outDir, { recursive: true });
  const zipPath = path.join(outDir, zipName);
  fs.writeFileSync(zipPath, buf);
  console.log(`已下载 ${buf.length} 字节 -> ${zipPath}`);

  // 提取 (尽力而为)
  const pw = password || 'hacktheblue';
  if (which('7z') || which('7zz')) {
    const cmd = which('7z') ? '7z' : '7zz';
    try {
      execFileSync(cmd, ['x', `-p${pw}`, `-o${outDir}`, zipPath, '-y'], { stdio: 'inherit' });
      console.log('已用 7z 解压 (密码 ' + pw + ')');
    } catch (e) {
      console.error('7z 解压失败: ' + e.message);
    }
  } else if (which('unzip')) {
    try {
      execFileSync('unzip', ['-P', pw, '-o', zipPath, '-d', outDir], { stdio: 'inherit' });
      console.log('已用 unzip 解压 (密码 ' + pw + ')');
    } catch (e) {
      console.error('unzip 解压失败: ' + e.message);
    }
  } else {
    console.log('未找到 7z/unzip, 仅保留 zip。密码默认 ' + pw + ' (可用 --password 覆盖)');
  }
}

async function submit(id, token, task, answer) {
  const tasks = await getTasks(id, token);
  const target = tasks.find(t => String(t.id) === String(task)) || tasks[Number(task) - 1];
  if (!target) {
    console.error(`找不到任务 '${task}'。可用任务:`);
    tasks.forEach((t, i) => console.error(`  ${i + 1} (id ${t.id}): ${t.title}`));
    process.exit(2);
  }
  const res = await fetch(`${BASE}/api/v4/sherlocks/${id}/tasks/${target.id}/flag`, {
    method: 'POST',
    headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ flag: answer }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { _raw: text }; }
  if (res.status === 201 && /owned/i.test(json.message || '')) {
    console.log(`✅ ${target.title} 通过: ${answer}`);
  } else if (res.status === 429) {
    console.error('⚠️ 限流 (x-ratelimit 30/分钟), 稍后重试');
  } else {
    console.log(`❌ ${target.title} 错误: ${answer}  (${json.message || text})`);
  }
}

async function submitFile(id, token, file) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  const tasks = await getTasks(id, token);
  const entries = [];
  for (const [k, v] of Object.entries(data)) {
    const t = tasks.find(x => String(x.id) === String(k)) || tasks[Number(k) - 1];
    if (!t) { console.error(`跳过未知任务键 '${k}'`); continue; }
    entries.push([t, v]);
  }
  // 串行提交避免限流
  for (const [t, ans] of entries) {
    await submit(id, token, t.id, String(ans));
    await new Promise(r => setTimeout(r, 300));
  }
}

const [, , cmd, arg1, arg2, arg3] = process.argv;
const idx = process.argv.indexOf('--token');
const token = getToken(idx >= 0 ? process.argv[idx + 1] : null);
const passwordIdx = process.argv.indexOf('--password') >= 0 ? process.argv.indexOf('--password') : process.argv.indexOf('-p');
const password = passwordIdx >= 0 ? process.argv[passwordIdx + 1] : null;
const outIdx = process.argv.indexOf('-o');
const outDir = outIdx >= 0 ? process.argv[outIdx + 1] : './sherlock-work';

if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') usage();

(async () => {
  switch (cmd) {
    case 'info': {
      const meta = await resolveId(arg1, token);
      const { json: play } = await apiJson(`/api/v4/sherlocks/${meta.id}/play`, token);
      console.log(`# ${meta.name} (id ${meta.id}, ${meta.difficulty}, rating ${meta.rating})`);
      if (play.data) {
        console.log(`附件: ${play.data.file_name} (${play.data.file_size})`);
        console.log('\n## 场景\n' + (play.data.scenario || '(无)'));
      }
      const tasks = await getTasks(meta.id, token);
      console.log('\n## 任务');
      tasks.forEach((t, i) => {
        console.log(`\n${i + 1}. [id ${t.id}] ${t.description}`);
        if (t.hint) console.log(`   hint: ${t.hint}`);
        console.log(`   mask: ${t.masked_flag}`);
      });
      break;
    }
    case 'tasks': {
      const meta = await resolveId(arg1, token);
      const tasks = await getTasks(meta.id, token);
      tasks.forEach((t, i) => console.log(`${i + 1}\t${t.id}\t${t.masked_flag}\t${t.description}${t.hint ? '  [hint: ' + t.hint + ']' : ''}`));
      break;
    }
    case 'download': {
      const meta = await resolveId(arg1, token);
      await download(meta.id, token, password, outDir);
      break;
    }
    case 'submit': {
      const meta = await resolveId(arg1, token);
      await submit(meta.id, token, arg2, arg3);
      break;
    }
    case 'submit-file': {
      const meta = await resolveId(arg1, token);
      await submitFile(meta.id, token, arg2);
      break;
    }
    case 'progress': {
      const meta = await resolveId(arg1, token);
      const { json } = await apiJson(`/api/v4/sherlocks/${meta.id}/progress`, token);
      const d = json.data || {};
      console.log(`${meta.name}: owned=${d.is_owned}  ${d.tasks_answered}/${d.total_tasks}  progress=${d.progress}%  rank=${d.own_rank}`);
      break;
    }
    default:
      console.error(`未知命令: ${cmd}`);
      usage();
  }
})().catch(e => { console.error('错误: ' + e.message); process.exit(1); });
