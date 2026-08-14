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
- название алгоритма: `Kuznyechik` в тексте и `kuznyechik` в коде.

## Текущее содержимое

- Streebog-256 и Streebog-512;
- ГОСТ Р 34.10-2012/256: открытый ключ, подпись и проверка на CryptoPro
  XchA paramSet;
- ГОСТ Р 34.10-2012/256 на TC26 paramSetA;
- ГОСТ Р 34.10-2012/512: открытый ключ, подпись, проверка и VKO на paramSetA;
- Kuznyechik, OMAC, CTR-ACPKM и KExp15/KImp15;
- HMAC, KDF_TREE, TLS PRF и TLSTREE для TLS-ГОСТ.

Для CryptoPro XchA используется ECCKiila/Fiat backend при наличии
`__int128`; на остальных платформах остаётся generic ECC fallback.

Эти функции используются патчем mbedTLS для шифронабора
`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` (`0xc100`). mbedTLS собирается
с установленными заголовками и статической библиотекой `libpogost`.

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
