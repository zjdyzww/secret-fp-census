# 误报普查：9 个安全扫描器仓库的实测数据

> 一句话结论：**在 9 个真实安全工具仓库上，我的规则报了 33 条"疑似密钥"，逐条判定后 0 条是真泄露——33 条全部是它们自己的检测规则文件。**

## 为什么做这个普查

GitHub 上关于"密钥扫描误报"的真实 issue 很多（搜 `secret scanning false positive` 有 22 个仓库在提），
但**没有人给出误报到底占多少、都是什么类型**的实测数据。所以我扫了一批真实仓库，把数据摊开。

## 方法（可复现）

1. 选 9 个公开的安全/扫描类仓库（名单见 `scanned-repos.txt`），`git clone --depth 1`
2. 用 `review.mjs` 跑一遍（只读，本地，不上传任何代码）
3. 每条候选按 6 类语境分诊：测试夹具 / 扫描规则 / 文档模板 / 构建产物 / 检测器自身 / 知识库快照

## 结果

| 指标 | 数值 |
|---|---|
| 扫描仓库 | 9 个 |
| 扫描文件 | 240 |
| **疑似密钥候选** | **33** |
| **真泄露** | **0** |
| 分诊：扫描规则文件 | 33 |
| 分诊：其余五类 | 0 |

**逐仓库明细**（真泄露全部为 0，故只列候选数）：
```
deepfence/SecretScanner        0 候选
dwisiswant0/apkleaks           2 候选（config/regexes.json —— 它自己的正则定义）
EwenQuim/entropy               0
hannob/snallygaster            0
liamg/dismember                0
redhuntlabs/BucketLoot         0
techjacker/repo-security-scanner 0
tillson/git-hound             31 候选（rules/*.yml —— 它自己的签名规则）
trufflesecurity/force-push-scanner 0
```

## 这个数据说明了什么

**扫描器互相扫对方，几乎必然"发现密钥"**——因为规则文件里写的就是"密钥长什么样"的正则。
这不是谁的错，是**缺少语境判定**的必然结果。

如果按误报率算：33/33 = **100% 误报**（在这批仓库上）。

## 这个数据**不**说明什么（重要）

1. 不说明这些仓库安全——它们把密钥放在别处，或者我覆盖的 6 类特征没命中；
2. 不说明这些工具差——它们扫的是**全 git 历史**，我只扫了工作树；
3. 不代表全行业误报率——这是 9 个**安全工具仓库**，本身是误报率最高的样本；
4. 样本极小（9 个仓库 / 240 文件），**不足以外推**。

## 复现

```bash
git clone --depth 1 https://github.com/tillson/git-hound.git
node review.mjs git-hound --json
# → 31 条候选，全部 triage=rulefile，critical=0
```

## 我在这次普查里修掉的自己的 bug

- 起初 `git-hound` 报 31 条"真高危"→ 分诊漏了 `rules/*.yml` 这类**签名规则文件** → 已补 `rules|signatures|patterns|detectors` 目录与 `*.regex(es)?|*.patterns?` 文件名识别
- 起初 `apkleaks` 报 2 条 → `config/regexes.json` 未识别 → 已补文件名规则

**这两个 bug 是普查捡出来的，不是我想出来的。**
