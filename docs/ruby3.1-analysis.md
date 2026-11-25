# ReDoS-анализ `ruby3.1` 3.1.2-7+deb12u1.astra16

Анализ исходников Debian-пакета Ruby 3.1.2 (Astra-патчи) статическим анализатором regexp + динамической проверкой на реальном Ruby (Onigmo 3.1.2). Из обхода исключены `test/`, `spec/`, `sample/`, `benchmark/`, `basictest/`, `bootstraptest/`, `.bundle/`, `coverage/`, `doc/`, `man/`, `win32/`, `cygwin/` и quilt-бэкапы `.pc/`.

## 1. Сводка

| Метрика | Значение |
| --- | --- |
| Просканировано файлов | 1246 |
| Извлечено кандидатов | 2909 (1806 уникальных шаблонов) |
| Подозрительных статически | 633 |
| Проверено динамически | 203 |
| **Подтверждено динамикой** | **5** |
| Совпало с known-базой | 7 |
| Находок в отчёте | 371 |
| Длительность прогона | 97 c |

Сложность по статике: `exponential` 25, `polynomial` 182, `unknown` 164.

## 2. Известные уязвимости (найдены через known-базу)

Сканер не присваивает CVE автоматически: совпадение — это аннотация. Для каждой находки указано, насколько структурно она совпала с адвизори (`exact`/`canonical`/`shape`/`core`/`fuzzy`) и что показала динамика.

| Файл:строка | Адвизори | Тип матча | Динамика |
| --- | --- | --- | --- |
| `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:6` | CVE-2023-28755 | canonical | **confirmed** (polynomial) |
| `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:7` | CVE-2023-28755 | exact | inconclusive (unknown) |
| `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:98` | CVE-2023-36617 | exact | **confirmed** (polynomial) |
| `lib/ipaddr.rb:525` | H1-1485717-IPADDR-REDOS (CVE нет) | exact | **confirmed** (polynomial) |
| `lib/rdoc/comment.rb:106` | RDOC-CALL-SEQ-REDOS (CVE нет) | exact | **confirmed** (exponential) |
| `lib/uri/rfc3986_parser.rb:104` | CVE-2023-36617 | exact | **confirmed** (polynomial) |
| `tool/lib/webrick/httputils.rb:155` | CVE-2023-36617 | fuzzy | inconclusive (unknown) |

### 2.1 Что подтверждено, а что нет

- `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:6` — CVE-2023-28755: статика `exponential` (conf 0.92), динамика `confirmed` / `polynomial`, максимум 46 ms.
- `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:7` — CVE-2023-28755: статика `exponential` (conf 0.92), динамика `inconclusive` / `unknown`, максимум -.
- `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:98` — CVE-2023-36617: статика `polynomial` (conf 0.75), динамика `confirmed` / `polynomial`, максимум 624 ms.
- `lib/ipaddr.rb:525` — H1-1485717-IPADDR-REDOS: статика `polynomial` (conf 0.75), динамика `confirmed` / `polynomial`, максимум 722 ms.
- `lib/rdoc/comment.rb:106` — RDOC-CALL-SEQ-REDOS: статика `exponential` (conf 0.92), динамика `confirmed` / `exponential`, максимум 523 ms.
- `lib/uri/rfc3986_parser.rb:104` — CVE-2023-36617: статика `polynomial` (conf 0.75), динамика `confirmed` / `polynomial`, максимум 624 ms.
- `tool/lib/webrick/httputils.rb:155` — CVE-2023-36617: статика `polynomial` (conf 0.75), динамика `inconclusive` / `unknown`, максимум 1 ms.

Пояснения по известным записям:

- **CVE-2023-28755** (URI RFC3986). В дереве два экземпляра парсера: основной `lib/uri` уже содержит backport possessive-квантификаторов (`*+`, `++`), а vendored `lib/bundler/vendor/uri` (0.10.1) — уязвим. Строки 6/7 — уязвимый и относительный варианты одного выражения; официальный reproducer `https://example.com/dir/ + 'a'*N + '/##.jpg'` даёт квадратичный рост на vendored-копии.
- **CVE-2023-36617** (URI PORT). Оба парсера (`lib/uri` и vendored) содержат уязвимое `\A[ws]*\d*[ws]*\z`: `URI#port = ' '*N + '!'` квадратично замедляется. Оба подтверждены динамикой.
- **CVE-2023-28756** (Time.rfc2822). В `lib/time.rb:505` уже стоит исправленный вариант выражения, поэтому находки нет — негативный контроль сработал корректно.
- `tool/lib/webrick/httputils.rb:155` (`^\s+(.*?)\s*\z`) — fuzzy-совпадение с PORT-выражением (score 0.79 при пороге 0.78), динамика линейна (0.9 мс на 8192). Это шум нечёткого матчинга, а не экземпляр CVE-2023-36617: именно поэтому `auto_assign_cve` по умолчанию выключен.
- `lib/bundler/vendor/thor/lib/thor/util.rb:105` больше не связывается с `H1-1485717-IPADDR-REDOS`: core-совпадение для этой записи отключено (`match_core: false`), так как её фрагмент `X+Y*` слишком общий.

## 3. Новые / отсутствовавшие в базе уязвимости

Оба дефекта публично известны, но **CVE им не присвоен**, и в исходной known-базе сканера их не было — они добавлены в неё по результатам этого анализа. Оба подтверждены воспроизводимой деградацией. Именно эти две находки дают ответ на вопрос «что нового»: чисто неизвестных (не описанных публично) подтверждённых ReDoS в пакете не обнаружено.

### `lib/rdoc/comment.rb:106` — RDOC-CALL-SEQ-REDOS

- Регулярное выражение: `(^\s*\n)+^(\s*\w+)` (flags `s`)
- Вызов: `RDoc::Comment#extract_call_seq`; сложность по статике: `exponential`, уверенность 0.92
- Динамика: **exponential**, максимум 523 ms, точек измерений 10
- Сгенерированная атака (prefix + pump×N + suffix + breaker): `'\nxN!'`
- Замеры: n=18 → 33 ms, n=20 → 128 ms, n=22 → 525 ms, n=22 → 523 ms
- Известность: upstream fix — rdoc 6.5.0, коммит `1311ca8c50` (CVE не присвоен).

### `lib/ipaddr.rb:525` — H1-1485717-IPADDR-REDOS

- Регулярное выражение: `\A(0|[1-9]+\d*)\z`
- Вызов: `IPAddr#mask!` (из `IPAddr#initialize`); сложность по статике: `polynomial`, уверенность 0.75
- Динамика: **polynomial**, максимум 722 ms, точек измерений 10
- Сгенерированная атака (prefix + pump×N + suffix + breaker): `'1xN.'`
- Замеры: n=2048 → 49 ms, n=4096 → 197 ms, n=8192 → 748 ms, n=8192 → 722 ms
- Известность: HackerOne #1485717 закрыт как resolved только благодаря regexp memoization в Ruby 3.2; в 3.1 дефект остаётся.

## 4. Остальные подтверждённые находки (известные CVE)

- `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:6` — CVE-2023-28755, `polynomial`, 46 ms
- `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:98` — CVE-2023-36617, `polynomial`, 624 ms
- `lib/uri/rfc3986_parser.rb:104` — CVE-2023-36617, `polynomial`, 624 ms

## 5. Статические гипотезы, не подтверждённые динамикой

202 находок со статической оценкой `exponential`/`polynomial` не показали воспроизводимой деградации. Распределение по каталогам: `lib` 122, `tool` 54, `ext` 23, `enc` 3.

Причины, проверенные вручную:

- Отсутствие якоря `\z`: совпадение находится сразу, backtracking не возникает (`lib/bundler/source/git.rb:282`, `lib/bundler/source/git/git_proxy.rb:79`).
- Onigmo схлопывает вложенные non-capturing повторы в `lib/uri/rfc3986_parser.rb` (ABS_PATH/REL_PATH): формально опасная конструкция на практике линейна.
- Детерминированные разделители (`mailto`, `bytes=` в `net/http/header.rb`) делают разбиение входа однозначным.
- Библиотечные хелперы и строковые шаблоны сборки (`ext/`, `tool/`) обрабатывают доверенные данные.

Примеры (по убыванию статической уверенности):

- `lib/bundler/source/git.rb:282` — exponential, dynamic `inconclusive`: `^(\w+://)?([^/:]+:)?(//\w*/)?(\w*/)*`
- `lib/bundler/source/git/git_proxy.rb:79` — exponential, dynamic `inconclusive`: `(git version\s*)?((\.?\d+)+).*`
- `lib/bundler/vendor/uri/lib/uri/mailto.rb:148` — exponential, dynamic `inconclusive`: `\A(?:[^@,;]+@[^@,;]+(?:\z|[,;]))*\z`
- `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:7` — exponential, dynamic `inconclusive`: `\A(?<relative-ref>(?<relative-part>\/\/(?<authority>(?:(?<userinfo>(?:%\h\h|[!$&`
- `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:93` — exponential, dynamic `inconclusive`: `\A\/(?:%\h\h|[!$&-.0-;=@-Z_a-z~])*(?:\/(?:%\h\h|[!$&-.0-;=@-Z_a-z~])*)*\z`
- `lib/bundler/vendor/uri/lib/uri/rfc3986_parser.rb:94` — exponential, dynamic `inconclusive`: `\A(?:%\h\h|[!$&-.0-;=@-Z_a-z~])+(?:\/(?:%\h\h|[!$&-.0-;=@-Z_a-z~])*)*\z`
- `lib/net/http/header.rb:237` — exponential, dynamic `inconclusive`: `\Abytes=((?:,[ \t]*)*(?:\d+-\d*|-\d+)(?:[ \t]*,(?:[ \t]*\d+-\d*|-\d+)?)*)\z`
- `lib/uri/mailto.rb:148` — exponential, dynamic `inconclusive`: `\A(?:[^@,;]+@[^@,;]+(?:\z|[,;]))*\z`
- `lib/uri/rfc3986_parser.rb:99` — exponential, dynamic `inconclusive`: `\A\/(?:%\h\h|[!$&-.0-;=@-Z_a-z~])*(?:\/(?:%\h\h|[!$&-.0-;=@-Z_a-z~])*)*\z`
- `lib/uri/rfc3986_parser.rb:100` — exponential, dynamic `inconclusive`: `\A(?:%\h\h|[!$&-.0-;=@-Z_a-z~])+(?:\/(?:%\h\h|[!$&-.0-;=@-Z_a-z~])*)*\z`
- `tool/lib/core_assertions.rb:101` — exponential, dynamic `inconclusive`: `\A(?:\xef\xbb\xbf)?(\s*\#.*$)*(\n)?`
- `tool/lib/webrick/httputils.rb:177` — exponential, dynamic `inconclusive`: `\G((?:"(?:\\.|[^"])+?"|[^",]+)+)
                    (?:,\s*|\Z)`
- `tool/merger.rb:324` — exponential, dynamic `inconclusive`: `^diff --git a\/version\.h b\/version\.h\nindex .*\n--- a\/version\.h\n\+\+\+ b\/`
- `tool/rbinstall.rb:863` — exponential, dynamic `inconclusive`: `\A
        (\#!\/bin\/sh\n\#.*-\*-\s*ruby\s*-\*-.*\n)
        ((?:.*\n)*?\#!.*ru`
- `tool/ruby_vm/loaders/insns_def.rb:42` — exponential, dynamic `inconclusive`: `
    (?<comment>  /[*] [^*]* [*]+ (?: [^*/] [^*]* [*]+ )* /         ){0}
    (?<`

## 6. Воспроизведение

```bash
# CVE-2023-36617 — PORT (квадратичный рост, оба парсера)
ruby -ruri -rbenchmark -e 'u=URI.parse("http://example.com/"); puts Benchmark.realtime { (u.port = " "*32000 + "!") rescue nil }'

# CVE-2023-28755 — vendored bundler URI 0.10.1 (квадратичный рост)
ruby -I pkgs/ruby3.1-3.1.2/lib/bundler/vendor/uri/lib -rbenchmark \
  -e 'module Bundler; end; require "uri";
      p = Bundler::URI::RFC3986_Parser.new;
      s = "https://example.com/dir/" + "a"*8000 + "/##.jpg";
      puts Benchmark.realtime { p.parse(s) rescue nil }'

# rdoc / RDOC-CALL-SEQ-REDOS (экспоненциальный рост)
ruby -I pkgs/ruby3.1-3.1.2/lib -rrdoc -rrdoc/comment -rrdoc/any_method -rbenchmark -e 'c=RDoc::Comment.new("call-seq:\n" + "\n"*22 + "!\n\n"); m=RDoc::AnyMethod.new(nil,"x"); puts Benchmark.realtime { c.extract_call_seq(m) rescue nil }'

# ipaddr / H1-1485717 (квадратичный рост)
ruby -ripaddr -rbenchmark -e 'puts Benchmark.realtime { (IPAddr.new("0.0.0.0/" + "1"*32000 + ".")) rescue nil }'
```

## 7. Методика и ограничения

- Статика: собственный парсер regex → AST → NFA, подсчёт путей и структурные правила (вложенные квантификаторы, перекрытие классов, полиномиальные цепочки).
- Динамика: изолированное выражение исполняется реальным движком на наборе входов возрастающей длины; `confirmed` ставится только при воспроизводимой сверхлинейной деградации (устойчивая медиана log-log наклона), а не по одному таймауту.
- Для каждой известной записи в базе может быть опубликованный `witness` (prefix/pump/suffix/breaker); он ставится первым в список атак, потому что эвристика не всегда находит точный невалидный вход для больших рукописных выражений.
- Динамика проверяет именно regexp; достижимость атакуемого входа по коду оценена статически (`input_control`/`input_evidence`). У найденных дефектов источник помечен как `unknown`, но реальные вызовы (`RDoc::Comment#extract_call_seq`, `IPAddr.new` через `mask!`, `URI#port=`) воспроизведены отдельными скриптами.
- `exact`/`canonical`/`shape`/`core` — структурные совпадения; `fuzzy` может дать правдоподобную, но неверную связь с адвизори, поэтому такие находки остаются аннотацией низкой уверенности.
- Ruby 3.1 не имеет `Regexp.timeout` и regexp-memoization из 3.2, поэтому найденные зависимости практически значимы для этой ветки.
