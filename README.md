Рекомендую перед установкой выполнить полное обновление системы и перезагрузиться:
```sh
apt update && apt full-upgrade -y && reboot
```
Это обновит ядро и установит актуальные заголовки (linux-headers),
необходимые для сборки модуля AmneziaWG (DKMS).

После:
```sh
bash <(curl -sSL https://raw.githubusercontent.com/ShiffGray/awg-create/refs/heads/main/awgcreate.sh)
```

---

## CLI
Примеры команд скрипта:
```bash
## python3 awgcreate.py [опции]

# Можно примерно вот так вота создать интерфейс
python3 awgcreate.py --make awg1 -i 10.1.0.1/24,fd10:1::1/112 -p 44567 -l 99 --mtu 1388 --warp 3

# Создать пользователя с именем test на awg0
python3 awgcreate.py -s awg1 -a test
# Удалить пользователя test на awg0
python3 awgcreate.py -s awg1 -d test
# Пересгенерировать ключи пользователя test на awg0 (ну тоесть сбросить данные подключения пользователя/пересоздать его)
python3 awgcreate.py -s awg1 -u test

# Сгенерировать zip архив с конфигами и qr-код для пользователя test, так же можно сгенерировать только qr-коды через флаг -q
# и только конфиги через -c , а через флаг -o указываеться конкретный пользователь или список пользователей
# -o test,test2,test3 , без него генерация будет для всех пользователей
python3 awgcreate.py -s awg1 -z -o test
```
Да кстати если добавлять много пользователей то это можно сделать вот так:
```bash
for ip in $(seq 2 24); do
  python3 awgcreate.py -s awg1 -a "$ip"
done
```

Команды для управления самим интерфейсом:
```bash
# Запустить интерфейс
awg-quick up awg1
# Остановить
awg-quick down awg1

# Добавить интерфейс в автозагрузки
systemctl enable awg-quick@awg1
# Удалить
systemctl disable awg-quick@awg1
# Перезапустить
systemctl restart awg-quick@awg1

# Вывести список запущенных интерфейсов и пользователей
awg
```
