# KitoFtorVPN Desktop

Windows-клиент KitoFtorVPN на базе AmneziaWG 2.0.

## Возможности

- Подключение к VPN одним кликом
- Обход VPN для выбранных сайтов (split tunneling) — применяется на живом соединении, без переподключения
- Защита от утечек IPv6
- Автозапуск при старте Windows, в том числе свёрнутым в трей
- Автоподключение при запуске
- Хранение конфигов и токенов с шифрованием Windows DPAPI
- Авторизация: email, Google, Telegram, гостевой режим
- Автообновления через GitHub Releases

## Установка

Скачай последнюю версию `KitoFtorVPN-Setup.exe` со страницы [Releases](https://github.com/KitoFtorVPN/KitoFtorVPN-desktop/releases) и запусти.

Для работы приложения требуются права администратора (необходимы для создания TUN-интерфейса и настройки маршрутов).

## Требования

- Windows 10 / 11 x64

## Стек

- [Electron](https://www.electronjs.org/) — UI (HTML/CSS/JS)
- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) — VPN-движок (Go)
- [Wintun](https://www.wintun.net/) — TUN-драйвер
- [electron-builder](https://www.electron.build/) — сборка установщика
- [electron-updater](https://github.com/electron-userland/electron-updater) — автообновления

## Как это устроено

Приложение состоит из двух частей.

`kitoftor-tunnel.exe` — служба Windows, работающая в фоне под системной учётной записью. Она поднимает и опускает WireGuard-туннель, правит таблицу маршрутов и настраивает DNS. Служба создаётся один раз и дальше просто живёт в фоне, ничего не делая, пока туннель не нужен.

Electron-приложение — это интерфейс. С службой оно общается через именованный канал `\\.\pipe\KitoFtorVPNTunnel`, доступный только SYSTEM и администраторам: подключение, отключение, опрос состояния и обновление списка обхода передаются туда напрямую, без запуска отдельных процессов.

Обход VPN сделан через персональные маршруты: адреса из белого списка получают маршрут через физический шлюз, а он выигрывает у общего маршрута туннеля. Поэтому список меняется на лету, а конфигурация уходит в туннель нетронутой.

## Сборка из исходников

Требуется Node.js 24+ и Go 1.26+.

```bash
# Go-хелпер (собирается прямо в bin/, откуда его забирает electron-builder)
cd kitoftor-tunnel
go build -ldflags "-s -w" -o ..\bin\kitoftor-tunnel.exe .
cd ..

# Установка зависимостей
npm install

# Запуск в режиме разработки
npm start

# Сборка установщика
npm run dist

# Сборка и публикация релиза на GitHub (нужен GH_TOKEN)
npm run publish
```

Установщик появится в папке `dist/`.

В PowerShell команды `npm` может блокировать политика выполнения скриптов — тогда пиши `npm.cmd`.

## Структура

```
KitoFtorVPN/
├── main.js           — главный процесс Electron
├── preload.js        — IPC-мост для renderer-процесса
├── package.json      — зависимости и конфиг electron-builder
├── ui/               — HTML-страницы интерфейса
│   ├── login.html
│   ├── main.html
│   ├── settings.html
│   ├── whitelist.html
│   ├── update.html
│   └── import.html
├── kitoftor-tunnel/  — исходники Go-службы
│   ├── main.go
│   ├── go.mod
│   └── go.sum
├── bin/              — собранный Go-хелпер и TUN-драйвер
│   ├── kitoftor-tunnel.exe
│   └── wintun.dll
└── build/            — иконки приложения, трея и NSIS-скрипт
```

## Сайт

[kitoftorvpn.fun](https://kitoftorvpn.fun)
