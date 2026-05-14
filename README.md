
```sh
bash <(curl -sSL https://raw.githubusercontent.com/ShiffGray/awg-create/refs/heads/main/awgcreate.sh)
```

---

## CLI
Примеры команд скрипта:
```bash
## python3 awgcreate.py [опции]

# Создать серверный интерфейс с именем awg0, подсетью 10.1.0.0/24, портом 44567, лимитом скорости для пользователей 99Мб/сек,
# MTU 1388 и 3 WARP конфига между которыми будет балансироваться трафик пользователей
python3 awgcreate.py --make /etc/amnezia/amneziawg/awg1.conf -i 10.1.0.0/24 -p 44567 -l 99 --mtu 1388 --warp 3

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
После создания/удаления/пересоздания пользователя для применения настроек необходимо перезагрузить интерфейс!
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
