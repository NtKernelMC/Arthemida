# Artemis Project или же Проект Артемида
Статическая библиотека античита написанная на заказ для проекта MTA Province by NtKernelMC при участии holmes0 
(Бывшего спец.администратора MTA Province)

# Функционал античита
1. Сканер для обнаружения анонимных потоков в процессе
2. Защита против загрузки Proxy-DLLок в процесс
3. Защита от инжекта через глобальные хуки SetWindowsHookEx
4. Защита против DLL инжекта посредством запуска с фейк-лаунчера
5. Сканер памяти для обнаружения смапленных DLL образов
6. APC монитор против QueueUserAPC инъекций DLL библиотек
7. Сделана проверка адресов возвратов с важных игровых функций
8. Добавлена возможность отключения и перезагрузки античита
9. Организована безопасная работа с установкой и удалением хуков
10. Cканнер для защиты целостности памяти в местах хуков античита
11. Сигнатурный cканер модулей в PEB на предмет поиска известных читов

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
