# Artemis Project

Библиотека античита для MTA Province.

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
    if (artemis != nullptr)
    {
        if (artemis->type == ArtemisLibrary::DetectionType::ART_ILLEGAL_THREAD)
        {
            // Действия при обнаружении стороннего потока
        }
        //else if... так же с остальными детектами
    }
}

// Инициализация
static ArtemisLibrary::ArtemisConfig cfg;
cfg.DetectThreads = true; // обнаружение сторонних потоков
cfg.DetectModules = true; // обнаружение сторонних модулей
cfg.DetectAPC = true; // обнаурежение APC инеъкций
//... и остальные детекты, пока работает только то что из первого этапа
cfg.ThreadScanDelay = 1000; // задержка в сканировании потоков
cfg.ModulesWhitelist.push_back("yacl.asi"); // добавление в белый список модуля у которого нет экспортов, дабы избежать ложно-положительный детект
//... другие настройки, будут задокументированы после нужных этапов
cfg.callback = ArtemisCallback; // вышеприведенный коллбек

ArtemisLibrary* art = alInitializeArtemis(&cfg); // инициализация с конфигурацией

```
