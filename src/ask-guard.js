/**
 * dsh-htb-skills/ask-guard — 防止把解题责任推回给用户。
 *
 * 由来（2026-09-24 实测，ReaperTwo 会话导出）：
 *   preset persona 第 4 条已写明"绝不问提示"，但那轮 3 次 ask_user_question 里
 *   有一次的选项是「你提供 HTB 站内 Official Writeup（或告诉我 WP 里的 payload
 *   细节）」—— 这是把 writeup 当选项，本质是把解题责任推回用户。
 *
 * 结论：提示词只能降低概率，不能保证。所以给这件事一个机制，跟红线守卫共用
 * `ctx.tools.guard()`（单调、只能否决、拒绝理由直接回到模型）。
 *
 * 边界：只拦**明确**的求助措辞。正常提问（要不要 reset、要不要换机器、要跑
 * 多久）一律放行 —— 那些确实只有用户能拍板。
 */

/** Stable Cordis plugin name（将来若单独挂一行用得上）。 */
export const name = 'htb-ask-guard'

/** 依赖工具注册表。 */
export const inject = ['tools']

/** 被守卫的工具名。 */
export const ASK_TOOL = 'ask_user_question'

/**
 * 规则表。`re` 扫的是这次提问的**全部文本**（header + question + 每个选项的
 * label/description），所以只要有一个选项在要提示，整次提问就被否决。
 */
export const ASK_HINT_RULES = [
  {
    id: 'ask-for-writeup',
    // 🔴 只拦"索要内容"，不拦"问策略"。
    // 2026-09-25 修：原正则裸匹配 `官方 WP`，把「要不要参考官方 WP」这种
    // **合法提问**也拦了 —— 那是用户的选择（跟 reset / 换机器同类），
    // 跟"把答案要过来"是两回事。现在要求出现索取动词，或"WP 里的 payload"
    // 这种明确指向内容的措辞。
    re: new RegExp([
      // ① 索取动词 + writeup 词
      String.raw`(?:给|发|贴|提供|告诉|帮我找|帮我拿|你给|你提供|有没有|有无)[^\n]{0,20}(?:writeup|write-up|walkthrough|官方\s*WP|WP\b|题解|攻略)`,
      // ② writeup 词 + "里的 payload/细节"
      String.raw`(?:writeup|write-up|walkthrough|题解|攻略|官方\s*WP)[^\n]{0,10}(?:里|中)[^\n]{0,6}(?:payload|细节|内容|步骤|exp|exploit)`,
      // ③ writeup 词 + "在哪 / 是什么"
      String.raw`(?:writeup|write-up|walkthrough|题解|攻略|官方\s*WP)[^\n]{0,8}(?:在哪|在哪里|是什么|发我|给我)`,
    ].join('|'), 'i'),
    why: '索要 writeup / 题解的内容，等于把解题责任推回给用户。',
    fix: '删掉这个选项，自己继续：写出当前假设 → 列 ≥3 条还没试的路径 → 每条估时 → 挑最短的先做。'
      + '（只想问"这次练习要不要用 WP"的话，那是用户的选择，正常问即可。）',
  },
  {
    id: 'ask-for-hint',
    re: /给(?:我|点)?(?:一点)?提示|提示一下|给点方向|指个方向|告诉我怎么做|告诉我下一步|下一步该做什么|该怎么走|hint/i,
    why: '直接要提示或要下一步，等于放弃自主解题。',
    fix: '先自己走完排查流程；走完仍卡，就问"要不要 reset / 要不要换机器"这类只有用户能拍板的事。',
  },
  {
    id: 'ask-for-payload',
    // 与 ask-for-writeup 同一个原则：要求"索取动词"，或"payload 在哪/是什么"
    // 这种明确指向内容的措辞。裸的 `payload 细节` 会误伤"要不要用 WP 里的
    // payload"这类策略提问。
    re: new RegExp([
      String.raw`(?:给|发|贴|提供|告诉|帮我|你给|你提供|有没有|有无|我需要|我要)[^\n]{0,20}(?:payload|exp|exploit|利用|shellcode)`,
      String.raw`(?:payload|exp|exploit|利用|shellcode)[^\n]{0,8}(?:给我|发我|贴出来|是什么|在哪)`,
    ].join('|'), 'i'),
    why: '要 payload/exploit 细节是要答案，不是要决策。',
    fix: '把"要答案"换成"报进度 + 报卡点"：说明已试过什么、观测到什么、下一步打算试什么。',
  },
]

/**
 * 把一次 ask_user_question 调用的全部可见文本拼起来。
 * @param exec - 待分发的工具调用。
 * @returns 拼接文本；取不到时返回空串。
 */
export function askTextOf(exec) {
  const questions = exec?.arguments?.questions
  if (!Array.isArray(questions)) return ''
  const parts = []
  for (const q of questions) {
    if (!q || typeof q !== 'object') continue
    if (typeof q.header === 'string') parts.push(q.header)
    if (typeof q.question === 'string') parts.push(q.question)
    if (Array.isArray(q.options)) {
      for (const option of q.options) {
        if (typeof option?.label === 'string') parts.push(option.label)
        if (typeof option?.description === 'string') parts.push(option.description)
      }
    }
  }
  return parts.join('\n')
}

/**
 * 对一次提问求首个命中规则。
 * @param text - {@link askTextOf} 的结果。
 * @param rules - 生效规则表；省略则用内置 {@link ASK_HINT_RULES}。
 * @returns 命中的规则；未命中返回 undefined。
 */
export function checkAsk(text, rules = ASK_HINT_RULES) {
  if (!text) return undefined
  for (const rule of rules) {
    if (rule.re.test(text)) return rule
  }
  return undefined
}

/**
 * 组装给模型看的拒绝理由。
 * @param rule - 命中的规则。
 * @returns 单条拒绝理由。
 */
export function askDenyReason(rule) {
  return `提问被拒 [${rule.id}]：${rule.why}\n改成这样：${rule.fix}`
}

/**
 * 挂载提问守卫。
 *
 * Config:
 *   - `tools`（默认 ['ask_user_question']）：要守卫的工具名列表。
 * @param ctx - 带 `tools` 的宿主插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  const guarded = new Set(cfg.tools ?? [ASK_TOOL])

  ctx.tools.guard((exec) => {
    try {
      if (!guarded.has(exec?.name)) return undefined
      const hit = checkAsk(askTextOf(exec))
      return hit ? askDenyReason(hit) : undefined
    } catch {
      // fail-open：守卫坏了不能把提问能力整个锁死。
      return undefined
    }
  })
}
