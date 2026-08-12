# libpogost

Единая статическая библиотека чистой ГОСТ-криптографии без зависимостей.

Библиотека является общим источником криптографических алгоритмов для
`l2tap`, `hostap`, `wnam2` и других потребителей. Если прямое подключение
библиотеки невозможно, потребитель использует точную копию её исходников.

Основные требования:

- portable ready, musl first;
- криптографическое ядро без libc, malloc, pthread, OpenSSL и Linux headers;
- caller-owned buffers и минимальный публичный API;
- generic-реализация как эталон для SIMD и regression-тестов;
- название алгоритма: `Kuznechik` в тексте и `kuznechik` в коде.

## Текущее содержимое

```text
include/libpogost/     публичный API
src/generic/           эталонная generic-реализация и таблицы
src/x86_64/            x86-64 SSE2 backend
tests/                 известные векторы и differential-тесты
```

Проверка:

```sh
make test
make san
```

Перенесённые generic и SIMD-файлы сохраняют GPL-2.0-or-later лицензию
исходного Linux-кода.
