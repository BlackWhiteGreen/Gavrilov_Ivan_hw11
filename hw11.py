import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Загрузка данных из JSON-файла
file_path = 'botsv1.json'
with open(file_path, 'r', encoding='utf-8') as f:
    raw_data = json.load(f)

# Извлечение результатов и создание основного датафрейма
clean_data = [item['result'] for item in raw_data]
df = pd.DataFrame(clean_data)

# Функция для приведения данных в строковый формат
def normalize_val(val):
    if isinstance(val, list):
        return str(val[0])
    return str(val)

# Нормализация ключевых колонок для корректной фильтрации
df['EventCode'] = df['EventCode'].apply(normalize_val)
df['sourcetype'] = df['sourcetype'].apply(normalize_val)

# Анализ логов Windows: поиск запусков PowerShell и изменения прав доступа
win_suspicious = df[
    (df['sourcetype'] == 'WinEventLog:Security') &
    (
        (df['EventCode'] == '4703') |
        ((df['EventCode'] == '4688') & df['Process_Command_Line'].str.contains('powershell', case=False, na=False))
    )
].copy()
win_suspicious['Event_Label'] = "Win ID:" + win_suspicious['EventCode']

# Анализ DNS логов: поиск подозрительных доменов по тегам в eventtype
def check_dns(row):
    # Проверка принадлежности к DNS логам и наличие подозрительных тегов
    is_dns = row.get('LogName') == 'DNS' or 'dns' in str(row.get('sourcetype', '')).lower()
    if is_dns:
        etype = row.get('eventtype', [])
        tags = ['suspicious', 'dns_beaconing']
        if isinstance(etype, list) and any(tag in etype for tag in tags):
            return True
    return False

dns_suspicious = df[df.apply(check_dns, axis=1)].copy()
dns_suspicious['Event_Label'] = "DNS:" + dns_suspicious['QueryName'].apply(normalize_val)

# Объединение всех подозрительных событий в один набор для визуализации
all_suspicious = pd.concat([win_suspicious, dns_suspicious])
top_10_events = all_suspicious['Event_Label'].value_counts().head(10)

# Настройка стиля и создание графика для топ-10 событий
sns.set_theme(style="whitegrid")
plt.figure(figsize=(12, 6))

# Построение диаграммы
plot = sns.barplot(x=top_10_events.values, y=top_10_events.index, palette="flare")

plt.title('Топ-10 подозрительных событий безопасности (Win и DNS)', fontsize=16)
plt.xlabel('Количество инцидентов', fontsize=12)
plt.ylabel('Тип события / Домен', fontsize=12)

# Добавление числовых подписей к столбцам
for i in plot.containers:
    plot.bar_label(i, padding=3)

plt.tight_layout()
plt.show()