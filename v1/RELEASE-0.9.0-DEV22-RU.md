# ModKit 0.9.0-dev22

## Universal Full Metadata Catalog

Dev22 развивает universal resolver без привязки к конкретным приложениям или тестовым именам.
Drova/AFK и любые другие APK могут использоваться только как regression fixtures; production-логика не содержит специальных правил для них.

### Что изменено

- Каждый IL2CPP metadata-метод проходит потоковую индексацию и записывается в `analysis.methods.jsonl`.
- Полный каталог не ограничен shortlist/лимитом Menu Builder и не требует полезного имени метода.
- Для каждого метода отдельно фиксируются:
  - metadata identity/token;
  - CodeRegistration RVA и уникальность отображения;
  - принадлежность executable file-backed segment;
  - return/parameter ABI shape, когда MetadataRegistration позволяет его восстановить;
  - direct ARM64 BL observation и первый статический call-site;
  - structural/semantic/runtime статусы без смешивания уровней доказательств.
- Методы вне bounded typed window не теряются: ABI материализуется потоково и сразу сериализуется на диск.
- Обфусцированный метод вроде `a()` может получить подтверждённый адрес/ABI без какой-либо догадки о его назначении.
- Full catalog остаётся inspection/evidence surface: наличие адреса и ABI само по себе не делает метод selectable в Menu Builder.
- `analysis.methods.jsonl.idx` хранит byte offsets каждых 30 строк, поэтому Android открывает обычные страницы без полного повторного сканирования каталога.
- ZIP полного дампа теперь может включать `analysis.methods.jsonl` и `analysis.methods.meta.json`.

### Fail-closed правило

`runtimeConfirmed` никогда не выставляется статическим анализом. Семантика не выводится из одного имени или одного слабого контекста. Автоматическое действие разрешается только после прохождения отдельного binding/execution policy.
