# Artemis Project или же Проект Артемида

Статическая библиотека античита написанная на заказа для проекта MTA Province by NtKernelMC при участии holmes0 (Бывшего спец.администратора MTA Province) Поскольку заказ выполнялся аутсорсингом и никакого договора о не разглашении либо документов о патентации продукта нет - моя разработка находится здесь вполне законно как часть моего портфолио, очень жаль что заказчик превратил этот перспективный user-mode античит в нечто ужастное и близко не напоминающее оригинал. Свежесть проекта - 7ого августа, я уверен мой более старый вариант продукта гораздо стабильнее после того как мне пришлось увидеть результат работы Сержанура =) У меня есть и более свежие коммиты, планирую со временем улучшать своё детище и выражаю благодарность бывшему администратору провинции - holmes0 Я его научил всему и сам набрался не мало опыта в разработке античитов за многие годы, наверное 80% моего гитхаба забита только одними модулями к античитам когда я еще учился этому не лёгкому делу, забавно) Какая ирония, ведь я самоучка-читодел с 7-летним стажем в С++ согласился скооперироватся с игровым проектом чтобы помочь им защитится от таких же как я. Все кто это читает - можете считать это моим маленьким вступным манифестом. Этот опыт командной разработки оказался самым невероятным в моей жизни - почти 4 месяца труда. Получил я за античит всего лишь 50 тысяч но и это было не плохо учитывая что после разработки отдельных модулей - Артемида стала моим самым масштабным и значимым в жизни проектом и моим первым серьезным античитом, жаль что некомпетентный сотрудник JST Team решил всё так испортить своей некомпетентностью. Я разрешаю использовать своё детище всем проектам согласно публичной GPLv3 Лицензии. Очень обидно как такой перспективный проект решил избавится от моего со-разработчика променяв его на абсолютно некомпетентного в этом вопросе более знакомого сотрудника. Обращаюсь к владельцу проекта - запомни мои слова, блат и дедовщина когда то погубят твой проект, однако я не держу на тебя зла. Артемида это именно то чего так не хватало провинции и она могла принести мир и положить конец этой вражде между игроками и читерами, что могли бы привести нас к примирению, а ты просто взял и использовал своего же бывшего администратора и не абы кого - ты ему доверял и предлагал место в команде. Теперь я оставлю Артемиду опубликованной - чтобы каждый кто знает о ней и вашем проекте, мог извлечь урок из дружбы между волком и тигром. Так или иначе я получил бессценный опыт в разработке античитов и смог изменить своё мировозренние, теперь я вижу что не читеры были найвысшим злом а - Ты.

## Сборка и подключение

1. Собрать библиотеку [MinHook](https://github.com/TsudaKageyu/minhook)
2. Подсоединить .lib MinHook-a к целевому проекту (где будет использоваться данный АЧ)
3. Собрать ArtemisLib
4. Подсоединить .lib ArtemisLib-a к целевому проекту
5. Заинклудить Artemis.h (лежит в корневой директории) в целевой проект

## Тестирование

Собрать проекты Tester и Attacker.

#### Методы, которые не требуют дополнительных DLL:

1. Запустить Tester и Attacker
2. Выбрать нужный метод атаки в Attacker

#### Proxy DLL:
1. Собрать ProxyDLL
2. Переместить dxgi.dll в папку с Tester.exe
3. Запустить Tester

#### SetWindowsHookEx DLL:
1. Собрать SetWindowsHookExDLL
2. Переместить cheat.dll в папку с Attacker.exe
3. Запустить Tester и Attacker
4. Выбрать атаку SetWindowsHookEx


## Использование

```cpp
using namespace ART_LIB;

// Коллбек который решает что делать с нарушителем
void __stdcall ArtemisCallback(ArtemisLibrary::ARTEMIS_DATA* artemis)
{
	if (artemis == nullptr) return;
	switch (artemis->type)
	{
	case ArtemisLibrary::DetectionType::ART_APC_INJECTION:
		printf("DETECTED APC! (ARGUMENT: 0x%X | CONTEXT: 0x%X | PROC: %s)\n",
			get<0>(artemis->ApcInfo), get<1>(artemis->ApcInfo), get<2>(artemis->ApcInfo));
		break;
	case ArtemisLibrary::DetectionType::ART_MANUAL_MAP:
		printf("Detected MMAP! Base: 0x%X | Size: 0x%X | Rights: 0x%X\n",
			artemis->baseAddr, artemis->regionSize, artemis->MemoryRights);
		break;
	case ArtemisLibrary::DetectionType::ART_RETURN_ADDRESS:
		printf("Detected Return to Hack Function! Address: 0x%X\n", artemis->baseAddr);
		break;
	case ArtemisLibrary::DetectionType::ART_ILLEGAL_THREAD:
		printf("Detected Anonymous thread! Base: 0x%X | Size: 0x%X\n",
			artemis->baseAddr, artemis->regionSize);
		break;
	case ArtemisLibrary::DetectionType::ART_ILLEGAL_MODULE:
		printf("Detected Illegal module! Base: 0x%X | DllName: %s | Path: %s | Size: %d\n",
			artemis->baseAddr, artemis->dllName.c_str(), artemis->dllPath.c_str(), artemis->regionSize);
		break;
	case ArtemisLibrary::DetectionType::ART_FAKE_LAUNCHER:
		printf("Detected fake launcher!\n");
		break;
	case ArtemisLibrary::DetectionType::ART_MEMORY_CHANGED:
		printf("Detected Illegal module! Base: 0x%X | Rights: 0x%X | Size: %d\n",
			artemis->baseAddr, artemis->MemoryRights, artemis->regionSize);
		break;
	}
}

// Инициализация библиотеки античита с последующей его проверкой стабильности к перезагрузкам и выключению
static ArtemisLibrary::ArtemisConfig cfg;
cfg.hSelfModule = NULL;
cfg.callback = ArtemisCallback;
cfg.DetectThreads = true;
cfg.DetectModules = true;
cfg.DetectAPC = true;
cfg.DetectReturnAddresses = true;
cfg.DetectManualMap = true;
cfg.ThreadScanDelay = 1000;
cfg.ModuleScanDelay = 1000;
cfg.MemoryScanDelay = 1000;
cfg.ModulesWhitelist.push_back("yacl.asi"); // добавление в белый список модуля у которого нет экспортов, дабы избежать ложно-положительный детект
ArtemisLibrary* art = alInitializeArtemis(&cfg);
if (art != nullptr)
{
    printf("Artemis succefully initialized!\n");
    bool diss = DisableArtemis();
    if (diss) printf("Artemis was successfully disabled!\n");
    else printf("Failed to disable Artemis.\n");
    if (ReloadArtemis(&cfg) != nullptr) printf("Artemis library successfully reloaded!\n");
    else printf("Failed to reload Artemis library.\n");
    printf("Disable Artemis addr: 0x%X | Initialize Artemis Addr: 0x%X\n", (DWORD)&DisableArtemis, (DWORD)&alInitializeArtemis);
}
else printf("Failed to initialize library.\n");
