import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Загрузка данных из файла с логами
file_path = 'botsv1.json'

with open(file_path, 'r', encoding='utf-8') as f:
    raw_data = json.load(f)

# Нормализация данных, создаем список словарей извлекая только 'result'
clean_data = [item['result'] for item in raw_data]

# Создание датафрейма
df = pd.DataFrame(clean_data)

# Доступные источники логов
print("Доступные типы источников:", df['sourcetype'].unique())

# Фильтр, только WinEventLog
windows_logs = df[df['sourcetype'] == 'WinEventLog:Security']

# Количество событий по кодам (топ10)
top_events = windows_logs['EventCode'].value_counts().head(10)

print("Топ-10 событий Windows:")
print(top_events)

# Поиск конкретных "подозрительных" событий
suspicious_processes = windows_logs[
    (windows_logs['EventCode'] == '4688') &
    (windows_logs['New_Process_Name'].str.contains('powershell', case=False, na=False))
]

print(f"\nНайдено запусков PowerShell: {len(suspicious_processes)}")

# Код для DNS (демонстрация реализации, закомментирован т.к. в нашем датафрейме нет таких событий)
# dns_logs = df[df['sourcetype'] == 'stream:dns']

# Поиск редких доменов
# rare_queries = dns_logs['query'].value_counts()
# print(rare_queries[rare_queries == 1]) # Те, к которым обращались 1 раз

# Поиск длинных поддоменов (днс-туннелирование)
# dns_logs['query_length'] = dns_logs['query'].str.len()
# suspicious_dns = dns_logs[dns_logs['query_length'] > 50]

# Настройка стиля графического вывода
sns.set_theme(style="whitegrid")
plt.figure(figsize=(12, 6))

# Построение чарта для Топ-10 EventID
sns.barplot(x=top_events.index, y=top_events.values, palette="viridis")

plt.title('Топ-10 событий безопасности Windows (EventID)', fontsize=16)
plt.xlabel('Код события (EventID)', fontsize=12)
plt.ylabel('Количество', fontsize=12)
plt.show()