# EC-INTEGRA
![176a12e4-7bcb-4015-8b15-6ab9d2d9bff5](https://user-images.githubusercontent.com/76482784/197170508-a7b5c1c9-eef0-41e8-81e7-8692668282a2.jpg)
# TerminaTOR
#### Программа TerminaTOR для ОС Linux предназначена для определения сигнатур трафика запрещенной в РФ сети TOR внутри локальной сети
## Описание модулей программы
### Модуль загрузки базы адресов
#### Данный модуль выполняет загрузку найденных в предыдущих сессиях работы программы IP-адресов сети Тор в структуру внутри программы. Это необходимо для выполнения логики сравнения и категорирования найденных адресов на новые и старые, чтобы избежать повторов и связанных с этим ошибок.
### Модуль загрузки базы блокированных адресов
#### Модуль выполняет загрузку IP-адресов сети Тор, которые были заблокированы программой ранее (добавлены в сетевой экран или Firewall), в структуру внутри программы. Это необходимо, чтобы не засорять фильтры повторяющимися правилами. Адрес добавляется независимо от того новый он или старый для программы. Важно, чтобы в настройках была включена функция блокирования.
### Модуль запуска графического интерфейса
#### Модуль выполнят загрузку основного класса, связанного с логикой и инициализацией графического интерфейса, дальнейшее обращение к этому модулю в ходе работы программы, за исключением первого обращения, не инициализирует, а изменяет графический интерфейс. При первом запуске открывается основное окно
 ![image](https://user-images.githubusercontent.com/116355531/197225575-4f9b9b9e-90c2-4d2b-8058-68abfd524fc9.png "Основное оконо")
### Модуль поиска по сети
#### Выполняется обращение к библиотекам и некоторым функциям WireShark для получения необходимых сетевых пакетов в реальном времени (налету), в ходе этого обращения устанавливается: 
* Фильтр, который задается в настройках поиска программы;
* Тайм аут ожидания пакетов.
#### Если время ожидания заканчивается, а пакеты не были обнаружены, модуль автоматически перезагружается и снова ждет получения пакетов. Подходящие пакеты записываются в соответствующую структуру, а затем анализируются.
#### Анализ выполняется с целью определения источника и получателя пакета, это необходимо для верного определения IP-адресов сети Тор. Далее модуль запускает отдельные потоки блокирования адреса и разрыва соединения, для которых так же передаются отдельные параметры (параметры подключения по SSH для блокирования и параметры для запуска такого же модуля поиска с другими фильтрами и измененной логикой для реализации RST атаки на узел сети Тор), если данные функции были включены в настройках программы. После чего передается сигнал в модуль графического интерфейса (обработчик сигналов).
### Модуль поиска по дампу
#### Почти аналогичен модулю поиска по сети, за исключением того, что поиск выполняется по сетевому дампу, а анализатор не выполняет никаких дополнительных действий, кроме анализа, то есть не запускает новых потоков для разрыва соединений и блокирования адресов. Это модуль пассивного сниффинга пакетов по заранее подготовленным сетевым дампам, который выполняется лишь для определения наличия трафика сети Тор. Подходящие пакеты анализируются, IP-адреса сети Тор передаются в виде сигнала в модуль графического интерфейса (обработчик сигналов).
### Модуль настройки поиска
#### В данном модуле задаются параметры пакетов для их поиска, параметры SSH соединения для работы функции блокирования адресов, включаются и отключаются дополнительные функции программы, а также открывается графическое окно настроек поиска и графическое окно настроек SSH соединения. Все параметры записываются в структуры внутри программы, а затем используются ею до перезапуска.
***
![image](https://user-images.githubusercontent.com/116355531/197230599-8413f8d2-5670-46a0-82dc-f8ffd6a46c18.png "Графическое окно настроек поиска")
***
![image](https://user-images.githubusercontent.com/116355531/197231214-45707799-33ae-4d19-b8cb-0e27681529ae.png "Графическое окно настроек SSH соединения")
***
### Модуль настройки параметров сертификатов
#### В структуры внутри программы записываются данные для создания фильтра поиска, а именно: длина сертификата TLS 1.2, длина фрейма рукопожатия сертификата TLS 1.3, расширение имени сервера (начальное и конечное значение). Настройки по умолчанию – это актуальные на данный момент значения параметров для успешного определения трафика сети Тор.
### Модуль настройки SSH соединения
#### В структуры внутри программы записываются данные для осуществления соединения с сетевым устройством, а именно: адрес устройства, логин, пароль, порт. Так же указывается форматированный шаблон команды, которую необходимо отправить на устройство, для добавления адреса в правила сетевого экрана или Firewall.
### Модуль активации дополнительных функций
#### Присвоение некоторым логическим переменным программы значений True или False для включения и отключения, соответственно, таких функций, как: разрыв текущего соединения с сетью Тор по адресу посредством осуществления RST атаки, блокирование адреса сети Тор посредством добавления его в правила сетевого экрана или Firewall. При этом при включении последней описанной функции осуществляется запуск графического окна настроек SSH соединения и соответствующего модуля (рис.4.).
### Модуль обработчика сигналов
#### Полученные сигналы анализируются на предмет наличия в них команд, которые прописаны логикой программы. Если сигнал не содержит команд, то передающиеся в нем данные, а именно: адреса узлов сети Тор, принадлежность к версиям TLS сертификатов, ошибки; выводятся на экран (в основное графическое окно) для ознакомления пользователем. Если сигнал содержал команду, то происходят некоторые изменения в графическом окне программы. При этом полученные адреса анализируются и сравниваются с базами ранее полученных, для определения новизны. 
* Если адрес новый – он передается в модуль вывода сообщений пользователю, а сам адрес передается в модуль обновления базы адресов.
* Если адрес старый, то происходит только передача в модуль вывода сообщений.
### Модуль обновления базы адресов
#### Адреса, прошедшие проверку анализатором внутри модуля обработчика сигналов, и соответствующие требованиям данного модуля (однократное появление адреса), записываются в базу (файл), который затем используется при последующих запусках программы.
### Модуль вывода сообщений пользователю
#### Сигналы, прошедшие анализатор внутри модуля обработчика сигналов, выводятся в основное графическое окно в читаемом пользователем формате. Сохраняется разделение на новые и старые адреса, сохраняется принадлежность к версии сертификата TLS, а так же, при возможности, выводится более подробное описание ошибок.
***
![image](https://user-images.githubusercontent.com/116355531/197232595-479f0f6b-2420-4992-87e6-c48db15b1f72.png "Пример сообщений программы TerminaTOR")
***
### Модуль разрыва соединения по адресу
#### Данный модуль принимает следующие параметры: адрес, соединение с которым нужно разорвать, интерфейс, на котором осуществляется соединение, адрес сети, в которой это соединение осуществляется. Данные параметры необходимы для: осуществления разрыва соединения, осуществления фильтрации при отслеживании соединения, анализа пакетов, отслеживаемого соединения. На основе этих данных запускаются отдельные потоки разрыва соединения. Внутри них происходит сборка, согласно выявленной логике работы разрыва соединения самим браузером Тор, RST пакетов отдельно для каждого типа соединения (под типами подразумевается ответ на TLS и TCP пакеты) и их отправление по адресу узла сети Тор, для осуществления разрыва этого соединения.
### Модуль добавления адреса в сетевой экран
#### Данный модуль принимает следующие параметры: 
- Адрес и порт устройства сети, на которое будет отправлена команда; 
- Логин и пароль, необходимые для осуществления подключения к устройству по SSH; 
- Шаблон команды, которую необходимо отправить; 
- Адрес сети Тор, который необходимо добавить в сетевой экран или Firewall.
#### Внутри модуля осуществляется: установление соединения и передача команды, шаблон которой преобразуется в настоящую исполнительную команду, посредством добавления в него реального адреса сети Тор. В случае выявления ошибок происходит передача сигнала, содержащего в себе название ошибки и подробное ее описание, в модуль обработчика сигналов.
### Инициализация
#### Для работы программы TerminaTOR необходимо:
- Скачать исходный код программы;
- Установить зависимости исходного кода (библиотеки: pyshark, psutil, scapy, PyQt5 и PyQt5-tools, netifaces, paramiko, tkinter). Например: pip install pyshark;
- В консоли перейти в директорию с файлом исходного кода программы;
- Запустить исполняемый файл программы: sudo python TerminaTOR.py.