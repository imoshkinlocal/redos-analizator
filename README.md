# debian-redos

Двухэтапный сканер ReDoS-уязвимостей в исходных пакетах Debian-семейства
(Python, Ruby, PHP). На первом этапе регулярные выражения извлекаются из кода и
анализируются структурно (AST + Thompson NFA + правила), на втором —
подозрительные шаблоны исполняются в реальном движке на специально
сгенерированных строках, и деградация либо подтверждается измерениями, либо нет.

Проект не зависит от внешних Python-библиотек: ядро, NFA и отчёты написаны на
стандартной библиотеке. `PyYAML` используется, если установлен; иначе работает
встроенный парсер минимального подмножества YAML.

> **Статус MVP.** Сканер не интегрируется в `dpkg-buildpackage` и по умолчанию
> не присваивает CVE автоматически (авто-присвоение из known-базы — явный
> opt-in, см. «Сравнение с известными уязвимостями»). CVE-карта — необязательная
> аннотация. См. «Ограничения».

---

## Содержание

- [Что проверяется](#что-проверяется)
- [Архитектура](#архитектура)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Как принимается решение](#как-принимается-решение)
- [Отчёты](#отчёты)
- [Конфигурация](#конфигурация)
- [CVE-карта](#cve-карта)
- [Сравнение с известными уязвимостями](#сравнение-с-известными-уязвимостями)
- [Инкрементальный режим и кэш](#инкрементальный-режим-и-кэш)
- [Безопасность исполнения](#безопасность-исполнения)
- [Детектор: как это работает](#детектор-как-это-работает)
- [Ограничения](#ограничения)
- [Разработка и тесты](#разработка-и-тесты)
- [Пример использования в CI](#пример-использования-в-ci)

---

## Что проверяется

| Язык | Извлечение | Движок динамики | Особенности |
|---|---|---|---|
| Python | `ast`: литералы, алиасы импортов, `re.compile`, переменные окружения, f-strings/конкатенации, обёртки | `re` (stdlib) | при `import regex` используется модуль `regex` |
| Ruby | Ripper через `ruby_extract.rb`; fallback — построчный сканер | Onigmo (MRI 3.1) | `/m` — это dot-all (нормализуется в `s`); `o/u/n/e/s` отбрасываются с note |
| PHP | `token_get_all`: литералы, конкатенации, переменные, константы классов | PCRE2 (php-cli), Docker — fallback | паттерн передаётся вместе с делимитерами; поднимается `pcre.backtrack_limit` (ограничение фиксируется в результате) |

Сканируются исходники пакета, а не установленные бинарники. Каталог `debian/`
исключается. Поддерживаются `.dsc` (с `--unpack-dsc`), распакованное дерево с
`debian/control`, каталог с несколькими деревьями и обычный каталог/файл для
демо и тестов.

---

## Архитектура

```
             discovery                extraction                 static
 paths ──► PackageInfo ──► SourceFile ──► RegexCandidate ──► StaticAnalysis
 (.dsc,      (control,      (sha256,       (Python AST,       (AST rules +
  tree,       changelog,     language,      Ripper,            NFA ambiguity,
  dir)        files)         size)          token_get_all)     attack plans)
                                                                     │
                                              SQLite cache ◄─────────┤
                                                                     ▼
             reports ◄── correlate ◄── DynamicAnalysis ◄──── dynamic verifier
          (JSON/JSONL/               (verdict, severity)   (real engine, sizes,
           SARIF/HTML/                                      growth slope,
           summary)                                         stability rerun)
```

Ключевые модули:

| Путь | Назначение |
|---|---|
| `debian_redos/core/discovery.py` | поиск пакетов, метаданные, перечисление файлов, sha256 |
| `debian_redos/extractors/` | три экстрактора + классификация источника данных |
| `debian_redos/analyzers/regex_ast.py` | парсер диалектов, AST, метрики |
| `debian_redos/analyzers/nfa.py` | Thompson NFA, подсчёт путей, неоднозначность |
| `debian_redos/analyzers/heuristics.py` | структурные правила + evidence + attack plans |
| `debian_redos/analyzers/attacks.py` | генерация `prefix + pump*k + suffix + breaker` |
| `debian_redos/dynamic/verifier.py` | замеры, классификация роста, политика подтверждения |
| `debian_redos/workers/` | изолированные воркеры Python/Ruby/PHP |
| `debian_redos/core/database.py` | SQLite: запуски, файлы, findings, кэши |
| `debian_redos/core/correlate.py` | дедупликация, verdict/severity, CVE-аннотация |
| `debian_redos/core/known.py` | сравнение с базой известных ReDoS-адвизори |
| `debian_redos/data/known_redos.json` | встроенная база известных шаблонов |
| `debian_redos/core/pipeline.py` | оркестрация, инкрементальность, `--jobs` |
| `debian_redos/reports/` | JSON, JSONL, SARIF 2.1.0, HTML, summary |

---

## Установка

Требуется Python ≥ 3.9. Для динамической проверки — соответствующие
интерпретаторы (`python3` уже есть; `ruby`, `php-cli` — по желанию, иначе
соответствующий язык анализируется только статически).

```bash
git clone https://github.com/imoshkinlocal/redos-analizator.git
cd redos-analizator
python3 -m pip install -e .          # ставит команду debian-redos
# без установки:
python3 -m debian_redos.cli --help
```

На Debian и Ubuntu системный `pip` может отказать из-за PEP 668
(`externally-managed-environment`). Тогда нужен venv:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/debian-redos doctor
```

Проверка окружения:

```bash
debian-redos doctor
```

`doctor` показывает версии Python/Ruby/PHP/PCRE2, наличие Docker и
`dpkg-source`, путь к кэшу, доступность движков и число записей в базе
известных ReDoS-адвизори. PHP используется нативно, если есть в `PATH`;
Docker-образ `php:8.2-cli` — только fallback.

---

## Быстрый старт

```bash
# Полный скан распакованного дерева
debian-redos scan /path/to/package-1.0

# Только статика, без запуска движков (быстро, для инвентаризации)
debian-redos scan /path/to/package-1.0 --static

# Несколько пакетов, 4 процесса извлечения, отчёты в каталог
debian-redos scan /src/pkg-a /src/pkg-b --jobs 4 --output-dir /tmp/redos-reports

# Инкрементальный повторный скан (неизменённые файлы берутся из БД)
debian-redos scan /path/to/package-1.0 --mode incremental

# Разобрать один шаблон
debian-redos analyze-pattern '^(a+)+$' --language python
debian-redos analyze-pattern '^(a|aa)+$' --language ruby --json

# Подтвердить деградацию в реальном движке
debian-redos verify '^(a+)+$' --language python

# Пересобрать отчёты из сохранённого запуска
debian-redos report --run-id run-abc123 --format html
```

Коды возврата `scan`:

| Код | Значение |
|---|---|
| `0` | сканирование успешно, findings ниже `--fail-on` |
| `1` | есть findings с severity ≥ `--fail-on` (по умолчанию `high`) |
| `2` | ошибка конфигурации/ввода |

Пример вывода:

```
  severity: critical=3, high=1
  verdict:  confirmed=1, exploitable=3
  critical  exploitable   exponential  pkg/app.py:10   ^(a+)+$
```

---

## Как принимается решение

`confirmed` ставится **только** при воспроизводимой деградации:

- экспоненциальный рост: минимум две измеримые точки, наклон log-log ≥ 3 и
  абсолютное время ≥ 5 мс;
- полиномиальный: наклон ≥ 1.6 и ≥ 10 мс;
- таймаут сам по себе недостаточен: нужна предыдущая точка ≥ 20 мс или
  наклон ≥ 2.5;
- повторные замеры одной длины схлопываются по минимуму: шум и throttling
  могут только добавить время, поэтому один сбойный rerun не превращает
  квадратичную кривую в «экспоненциальную»;
- наклон считается как медиана последних трёх log-log отрезков, чтобы один
  шумный хвост не менял класс роста;
- выполняется повторный замер самой медленной точки (stability rerun);
  отношение времён должно быть ≤ 2.

Матрица итоговых вердиктов:

| Условие | Verdict | Severity (exp / poly) |
|---|---|---|
| деградация подтверждена + `user_network`/`user_local` | `exploitable` | critical / high |
| деградация подтверждена, источник — файл/БД/ENV | `confirmed` | high / medium (на шаг ниже) |
| деградация подтверждена, источник неизвестен | `confirmed` | high |
| статика: экспоненциальный шаблон, источник `unknown`, динамика не подтвердила | `needs_review` | medium |
| статика: опасная форма, но подтверждения нет | `potential` | medium / low |
| статика: неизвестные конструкции (backrefs, рекурсия) | `needs_review` | medium / low |
| шаблон безопасен | `informational` (только при `static.report_safe: true`) | info |

`input_control` — лёгкая **внутрифайловая** классификация с evidence: сеть
(`request.args`, `$_GET`, `params[`), локальный ввод (`sys.argv`, `gets`,
`$argv`), файл, ENV, БД, литерал (`internal`). Межфайловый dataflow не
строится сознательно.

Дедупликация: одинаковый шаблон (dialect + flags + нормализованный pattern) в
одном файле даёт один finding; локации объединяются, `duplicates` показывает
число дополнительных мест, `input_control` выбирается по наиболее опасному
источнику. Одинаковые шаблоны в разных файлах остаются разными findings.

---

## Отчёты

По умолчанию в `reports/` (настраивается `output.dir` и `--output-dir`):

| Файл | Формат |
|---|---|
| `redos-report.json` | полный результат: пакеты, статистика, findings, config |
| `redos-findings.jsonl` | первая строка — метаданные запуска, далее по finding на строку |
| `redos.sarif` | SARIF 2.1.0 для GitHub/GitLab code scanning |
| `redos-report.html` | автономный HTML с фильтрами (без внешних ресурсов) |
| `redos-summary.txt` | текстовая сводка |
| `manifest.json` | список созданных отчётов и статистика |

Выбрать форматы: `--format json --format sarif`, отключить отчёты:
`--no-reports`. JSON/JSONL — стабильный машинный интерфейс; SARIF пригоден для
загрузки в системы code scanning.

Фрагмент finding:

```json
{
  "id": "sha256:...",
  "package": "demo",
  "version": "1.0-1",
  "language": "python",
  "file": "app.py",
  "line": 10,
  "function": "handler",
  "engine": "python-re",
  "pattern": "^(a+)+$",
  "input_control": "user_network",
  "static": {
    "status": "vulnerable",
    "complexity": "exponential",
    "confidence": 0.92,
    "evidence": [{"rule": "nested_quantifier", "message": "..."}],
    "attack_plans": [{"prefix": "", "pump": "a", "suffix": "", "breaker": "!"}]
  },
  "dynamic": {
    "status": "confirmed",
    "growth_class": "exponential",
    "growth_slope": 15.6,
    "max_elapsed_ms": 841.2,
    "trials": [{"input_length": 24, "elapsed_ms": 841.19, "status": "completed"}]
  },
  "verdict": "exploitable",
  "severity": "critical",
  "known": [
    {
      "id": "CVE-2023-28756",
      "cve": "CVE-2023-28756",
      "title": "ReDoS in Ruby Time.rfc2822 date parsing",
      "kind": "exact",
      "score": 1.0,
      "confidence": "high",
      "match_types": ["exact"],
      "pattern_matched": true,
      "auto_assigned": false
    }
  ]
}
```

---

## Конфигурация

`config/scanners.yaml` мержится с встроенными значениями
(`debian_redos/config.py`). Все ключи необязательны. Изменение секций
`languages`, `limits`, `static`, `dynamic` меняет `config_hash` и инвалидирует
кэши; `output`, `severity`, `cve`, `known` на кэш не влияют (known-аннотации
пересчитываются каждый запуск).

Основные параметры:

```yaml
limits:
  max_pattern_length: 4096
  max_input_length: 8192
  timeout_seconds: 2.0            # предел одного замера
  candidate_budget_seconds: 8.0   # предел на весь кандидат
  max_memory_mb: 256

dynamic:
  enabled: true
  use_docker_for_php: true
  php_docker_image: "php:8.2-cli"
  max_candidates_per_finding: 4
  growth:
    noise_floor_ms: 0.5
    confirm_ratio: 2.5
    min_points: 3
  sizes:
    exponential: [8, 10, 12, 14, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 96, 128]
    polynomial:  [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]

static:
  report_safe: false
  min_severity_to_report: info

cache:
  enabled: true
  path: .redos-cache/redos.sqlite3

output:
  dir: reports
  json: true
  jsonl: true
  html: true
  sarif: true
  summary: true
```

Для стабильных замеров оставляйте `--dynamic-jobs 1` (по умолчанию): несколько
одновременных движков конкурируют за CPU и увеличивают шум.

Секция `known` (сравнение с известными адвизори) описана в разделе
[«Сравнение с известными уязвимостями»](#сравнение-с-известными-уязвимостями).

---

## CVE-карта

CVE-карта только аннотирует находки и не меняет verdict. Авто-присвоение CVE из
known-базы по умолчанию выключено (см.
[«Сравнение с известными уязвимостями»](#сравнение-с-известными-уязвимостями)).
Необязательный JSON-файл позволяет аннотировать уже известные находки; поиск
идёт от точной локации к pattern hash, затем к пакету:

```json
{
  "locations": {
    "demo:app.py:10": {"cve": "CVE-2021-0001", "source": "https://tracker/..."}
  },
  "patterns": {
    "sha256:...": {"cve": "CVE-2021-0002", "source": "vendor advisory"}
  },
  "packages": {
    "demo": [{"cve": "CVE-2021-0003", "file": "old.py", "source": "notes"}]
  }
}
```

Указать файл: `debian-redos --config my.yaml scan ...`, где `cve.db:
/path/cve-map.json`.

---

## Сравнение с известными уязвимостями

Помимо CVE-карты (точная локация → CVE) сканер умеет сравнивать найденный
шаблон с локальной базой известных ReDoS-адвизори. Это отвечает на вопрос
«мы нашли `(a|aa)+` в `ruby3.1` — не тот ли это паттерн, который уже закрывали
в CVE-2023-XXXX?». Сравнение многоуровневое, потому что уязвимую конструкцию
почти никогда не копируют дословно.

| Уровень | Что означает | Пример |
|---|---|---|
| `exact` | совпали шаблон, диалект и набор флагов | побайтово тот же `PORT` |
| `canonical` | шаблон семантически эквивалентен после разбора | `\A(a|aa)+\z` ≡ `\A(?:a|aa)+\z`, `(?P<x>…)` ≡ `(?<y>…)` |
| `shape` | совпала структура, а литералы/классы абстрагированы | `^(a+)+:(b+)+$` ≈ `^(x+)+-(y+)+$` |
| `core` | присутствует та же опасная подконструкция, обрамление другое | `^X(a+)+Y$` ≈ `\Afoo(a+)+bar\z` |
| `fuzzy` | высокая текстово-структурная близость (мелкие правки) | `^([a-z]+)+\d$` ≈ `^([a-z]+)+\d\d$` |
| `package` | у адвизори нет паттерна, совпал только исходный пакет | `ruby3.1` → адвизори `ruby` |

Уровни складываются: у одного матча `match_types` может содержать сразу
`["canonical", "shape", "core", "fuzzy"]`, а `kind` — самый сильный из них.
`package`-совпадения всегда имеют `pattern_matched: false` и низкую
уверенность.

### Встроенная база

`debian_redos/data/known_redos.json` содержит проверенные Ruby-адвизори с
реальными шаблонами из `lib/time.rb` и `lib/uri/rfc*_parser.rb`:

- `CVE-2023-28755` — ReDoS в URI RFC3986-парсере (уязвимый и исправленный
  варианты больших выражений);
- `CVE-2023-28756` — ReDoS в `Time.rfc2822`;
- `CVE-2023-36617` — неполный фикс URI (rfc2396/rfc3986; possessive-квантификаторы
  в whitespace-цепочках);
- `RDOC-CALL-SEQ-REDOS` — ReDoS в `RDoc::Comment#extract_call_seq` (без CVE;
  исправлено upstream в rdoc 6.5.0 коммитом `1311ca8c50`);
- `H1-1485717-IPADDR-REDOS` — ReDoS в `IPAddr#mask!` (без CVE; HackerOne
  #1485717, исправлено только memoization-оптимизацией Ruby 3.2, поэтому 3.1
  остаётся уязвим).

Для каждой записи хранятся и `vulnerable`, и `fixed`-варианты паттернов.
**Сопоставляются только `vulnerable`**, поэтому дерево, где уже лежит
исправленное выражение, не будет помечено.

У уязвимого паттерна может быть необязательный `witness` — опубликованный
reproducer в форме `prefix`/`pump`/`suffix`/`breaker`/`kind`. Динамическая
стадия ставит его первым в список атак, потому что эвристический witness для
больших рукописных выражений (например, RFC3986) часто не воспроизводит
дефект. Запись может содержать `"match_core": false`, если её core-фрагмент
слишком общий и даёт cross-advisory ложные срабатывания.

### Формат базы

```json
{
  "schema_version": "1.0",
  "updated": "2026-11-06",
  "entries": [
    {
      "id": "CVE-2023-28756",
      "cve": "CVE-2023-28756",
      "title": "ReDoS in Ruby Time.rfc2822 date parsing",
      "language": "ruby",
      "severity": "high",
      "packages": ["ruby", "ruby-time", "time"],
      "affected": ["ruby < 3.1.4", "time gem < 0.2.2"],
      "references": ["https://..."],
      "notes": ["..."],
      "patterns": [
        {"pattern": "\\A\\s*...", "flags": "ix", "status": "vulnerable",
         "witness": {"prefix": "", "pump": " ", "suffix": "!", "kind": "polynomial"}},
        {"pattern": "\\A\\s*...", "flags": "ix", "status": "fixed"}
      ]
    }
  ]
}
```

`language` может быть `"any"`; у паттерна можно задать собственный `dialect`.
`status`: `vulnerable` | `fixed` | `test`. Запись без `patterns` — это
package-only адвизори (например, когда фикс был ограничением длины входа, а не
правкой regexp).

### CLI

```bash
# статистика и список базы (bundled или known.db из конфигурации)
debian-redos known stats
debian-redos known list --language ruby --severity high
debian-redos known show CVE-2023-28756 --full
debian-redos known check                 # валидация JSON-базы

# сравнить произвольный шаблон
debian-redos known match '\A[\x09\x0a\x0c\x0d ]*\d*[\x09\x0a\x0c\x0d ]*\z' \
    --language ruby --package ruby3.1

# смержить/расширить локальную базу
debian-redos known import my-advisories.json --output known.json --dry-run
debian-redos known import my-advisories.json --output known.json
# новый файл по умолчанию = встроенная база + импортируемые записи;
# --empty создаёт базу только из импортируемых записей
```

`known` также печатается в `analyze-pattern`/`verify`, в `doctor` и в отчётах
(JSON, JSONL, SARIF `properties.known`, HTML-бейджи, секция «Known matches» в
summary).

### Политика CVE

Матч — это **аннотация, а не присвоение CVE**. `finding.known[]` заполняется
всегда, `finding.cve` — только если в конфигурации явно включено
`known.auto_assign_cve: true`. Даже тогда CVE берётся только из `exact` или
`canonical` матча с `score ≥ known.auto_assign_min_score` (по умолчанию 0.95),
и только если поле `cve` ещё пустое. `shape`/`core`/`fuzzy`/`package` никогда
не присваивают CVE. CVE-карта имеет приоритет над авто-присвоением.

### Пример

Скан дерева Ruby 3.1.0 находит в `uri/rfc3986_parser.rb`:

```text
rfc3986_parser.rb:6   canonical  CVE-2023-28755
rfc3986_parser.rb:7   exact      CVE-2023-28755
rfc3986_parser.rb:98  exact      CVE-2023-36617
rfc3986_parser.rb:104 exact      CVE-2023-36617
```

Строка 6 — семантически тот же паттерн, но записан чуть иначе, поэтому
сработал `canonical`, а не `exact`. На дереве Ruby 3.1.5 (с исправленными
`rfc3986_parser.rb`/`rfc2396_parser.rb`) эти совпадения исчезают.

### Ограничения и ложные срабатывания

- `core`/`shape`/`fuzzy` — эвристики: они отвечают «конструкция похожа», а не
  «это тот же баг». Для юридически значимых выводов используйте `exact`/
  `canonical` и ссылку на адвизори.
- `core` намеренно не матчит голые фрагменты (`\s*`, `(a+)`), иначе почти любой
  ReDoS совпадал бы с любым другим.
- Большие паттерны (> 2048 символов после нормализации) не проходят `fuzzy`,
  чтобы не тратить время на `difflib`; `exact`/`canonical`/`core` работают.
- Изменение базы не инвалидирует кэш (`config_hash` не включает `known`);
  переиспользованные findings переаннотируются при каждом запуске.
- Неизвестный диалект/неразобранный шаблон отключает структурные уровни —
  остаётся только `exact`.

Включение и настройка:

```yaml
known:
  enabled: true
  db: null                 # null => встроенная база
  min_score: 0.78          # порог fuzzy
  match_core: true
  match_packages: true
  max_matches: 5
  auto_assign_cve: false
  auto_assign_min_score: 0.95
```

---

## Инкрементальный режим и кэш

SQLite (`.redos-cache/redos.sqlite3` по умолчанию) хранит:

- `scan_runs` — запуски, конфигурация, статистика;
- `packages`/`files` — метаданные и sha256;
- `findings` — findings по запускам (ключ `(id, run_id)`, история сохраняется);
- `analysis_cache` — статический анализ по `(config_hash, dialect, flags,
  pattern_hash, лимиты)`;
- `dynamic_cache` — динамика по `(config_hash, pattern, engine identity,
  attack plans, настройки замеров)`.

`--mode incremental` переиспользует findings только для файлов с тем же sha256 и
при совпадении `config_hash`; при изменении файла он анализируется заново.
Первый запуск в режиме incremental без совместимого прошлого запуска
автоматически превращается в полный.

Обслуживание:

```bash
debian-redos db stats
debian-redos db runs
debian-redos db prune --keep 5
debian-redos db clear-cache
```

---

## Безопасность исполнения

Сканер **никогда не исполняет код из проверяемого пакета**. В движок передаются
только строка шаблона и сгенерированный вход.

- Python/Ruby/PHP-воркеры запускаются в отдельной process group;
- wall-clock таймаут → `SIGKILL` всей группы (`os.killpg`);
- до `exec` ставятся `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_CORE`, `RLIMIT_FSIZE`;
- PHP через Docker: `--network none`, `--read-only`,
  `--security-opt no-new-privileges`, лимиты памяти/CPU/PID;
- воркеры общаются JSON-lines через stdin/stdout, stderr подавлен;
- в результаты попадают только превью входных строк (≤ 80 символов), не полные
  payload'ы.

Ограничения всё же стоит учитывать: динамическая проверка намеренно создаёт
нагрузку (до `timeout_seconds` на замер и `candidate_budget_seconds` на
кандидата), поэтому сканируйте недоверенные пакеты в контейнере/CI-раннере с
лимитами CPU.

---

## Детектор: как это работает

1. **Парсер** (`regex_ast.py`) понимает группы (включая atomic/named),
   альтернацию, жадные/ленивые/possessive квантификаторы, классы символов,
   POSIX/Unicode-свойства, якоря, lookaround, backreferences и inline-флаги.
   Неподдерживаемые конструкции не роняют анализ, а помечаются `Unsupported`.
2. **Структурные правила** (`heuristics.py`):
   - `nested_quantifier` — вложенные неограниченные квантификаторы с
     пересечением первого/последнего символа;
   - `nullable_body` — квантификатор над телом, допускающим пустую строку;
   - `ambiguous_repetition` — измеренная неоднозначность повторяемого блока;
   - `bounded_ambiguous_repeat` — большое ограниченное повторение с внутренним
     неограниченным квантификатором;
   - `sequential_overlap` — два неограниченных квантификатора подряд, способных
     поглощать одни и те же символы (полиномиальный случай);
   - `backreference_in_repeat`, `unsupported_in_repeat` — требуют ревью.
   Atomic-группы и possessive-квантификаторы не дают обратного захвата и
   исключаются из экспоненциальных правил (`(?>a+)+`, `(a++)+` — safe).
3. **NFA/EDA** (`nfa.py`): Thompson NFA и подсчёт числа принимающих путей для
   одной строки. Это отличает `(a|aa)+` (неоднозначно: `aa` имеет два разбора)
   от `(ab|a)+` (однозначно), без хардкода форм. Ограничение состояний —
   `MAX_STATES` (6000), при превышении анализ помечается частичным.
4. **Attack plans** (`attacks.py`): для найденного повторения строится
   `prefix + pump*k + suffix + breaker` (несколько вариантов: с суффиксом, без
   суффикса, с укороченным pump). Именно эти строки исполняет динамика.
5. **Динамика** (`verifier.py`) увеличивает длину входа, замеряет реальное время,
   считает наклон log-log и применяет политику подтверждения. Для каждого
   finding сохраняются все trials.

---

## Ограничения

- Backreferences и рекурсия не моделируются точно: такие шаблоны попадают в
  `needs_review`/`unknown`, а не в «безопасные».
- Lookaround считается zero-width для потребляющего автомата; вложенные в него
  повторы всё равно обходятся AST-правилами.
- `^`/`$` и другие якоря — zero-width; NFA не моделирует multiline-семантику
  позиций.
- `input_control` — эвристика внутри файла; вызовы через обёртки, DI,
  ORM-маппинг и межфайловый dataflow не отслеживаются. Для Ruby источник
  уточняется по строке использования присвоенного regexp (например,
  `VULN = /.../; params[:q] =~ VULN`), но это не полноценный dataflow.
- Дедупликация намеренно консервативна: один шаблон в одном файле — один
  finding, разные файлы не объединяются.
- Ruby 3.1 не имеет `Regexp.timeout`; замеры ограничены внешним wall-clock
  kill. Поведение может отличаться от Ruby 3.2+.
- PHP-воркер поднимает `pcre.backtrack_limit` до `1e8`, иначе PCRE2 быстро
  возвращает ошибку и деградация не видна; фактическое значение фиксируется в
  результате.
- Динамические замеры чувствительны к нагрузке хоста. Для стабильности:
  `--dynamic-jobs 1`, не запускайте скан на перегруженной машине; при
  `not_confirmed` с высоким наклоном стоит перепроверить вручную.
- Внешние детекторы (Regexploit/ReDoSHunter/CodeQL) в конфиге предусмотрены, но
  не являются зависимостью и по умолчанию выключены.
- Автоматическое присвоение CVE по умолчанию выключено; при включении оно
  ограничено exact/canonical матчами. Интеграция в Debian build pipeline и
  синхронизация с CVE-трекерами — вне scope MVP.

---

## Разработка и тесты

```bash
python3 -m pytest                 # весь набор (включая динамические тесты)
python3 -m pytest -m "not slow"   # быстрые тесты без запуска движков
python3 -m compileall debian_redos
```

Тесты покрывают парсер и NFA, калибровочную матрицу эвристик, генерацию
attack-строк, экстракторы (включая fallback без интерпретаторов), воркеры и
политику подтверждения, discovery/фикстуру Debian-пакета, БД и инкрементальный
режим, дедупликацию/severity, все форматы отчётов и CLI end-to-end.

Структура тестовой фикстуры: `tests/fixtures/samplepkg/` (Debian control и
changelog + уязвимые Python/Ruby/PHP файлы).

---

## Пример использования в CI

```yaml
name: redos
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: sudo apt-get update && sudo apt-get install -y ruby php-cli
      - run: python -m pip install -e .
      - run: debian-redos scan . --mode incremental --fail-on high
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: redos-reports
          path: reports/
```

SARIF можно загрузить в GitHub code scanning или GitLab SAST; JSONL удобен для
последующей обработки, HTML — для ручного разбора. Пример реального прогона по
исходникам `ruby3.1` (1246 файлов, 5 подтверждённых деградаций) лежит в
[docs/ruby3.1-analysis.md](docs/ruby3.1-analysis.md).

## Лицензия

MIT, см. [LICENSE](LICENSE).
