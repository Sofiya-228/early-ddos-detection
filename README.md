# Early DDoS Detection from PCAP

Исследовательский Python-прототип обнаружения изменений сетевой активности по скользящим временным окнам. Используется пакетный захват **CIC-IDS2017 Friday-WorkingHours.pcap** (офлайн-воспроизведение, не захват живой сети).

## Возможности

- Извлечение IPv4-пакетов из PCAP через **TShark** и построение окон **2 с** с шагом **1 с**.
- Признаки: `packets_per_sec`, `bytes_per_sec`, `syn_per_sec`, `syn_ratio_tcp`, `unique_src_ips`, `unique_dst_ips`.
- Детекторы: **Threshold, EWMA, CUSUM, Isolation Forest, One-Class SVM**.
- Временное разделение нормального трафика на обучение и калибровку, отдельный последующий тест.
- Исследование 69 комбинаций параметров и порогов, уточнение времени первой тревоги, графики и метрики.

## Установка на Windows

Требуется Python 3.10+ и [Wireshark](https://www.wireshark.org/download.html) с `TShark`, `Editcap` и `Capinfos`. В скрипте `stage1.ps1` используется стандартный путь `C:\Program Files\Wireshark`.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
New-Item -ItemType Directory -Force -Path data\raw
```

Скачайте `Friday-WorkingHours.pcap` со [страницы CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) и поместите в `data/raw/Friday-WorkingHours.pcap`. PCAP не включён в репозиторий из-за размера и условий распространения набора данных.

## Запуск

Все команды из корня проекта:

```powershell
python main.py check       # проверить наличие данных
python main.py prepare     # выделить PCAP, сформировать окна и проверить данные
python main.py test        # тесты
python main.py run         # исходный эксперимент: 5 детекторов
python main.py research    # 69 вариантов параметров и признаков
python main.py onset       # уточнённая разметка, задержки и графики первых тревог
```

Если признаки `data/processed/friday_2s.csv` уже рассчитаны, команды `run`, `research` и `onset` не требуют повторной обработки PCAP.

## Структура

```text
main.py                    Точка входа
config.json                Временные границы и параметры
stage1.ps1                 Выделение PCAP и извлечение признаков
stage2.py                  Первоначальное сравнение пяти методов
pcap_research_next.py      Эксперимент с параметрами и группами признаков
pcap_check_onset.py        Уточнение разметки и первых тревог
inspect_features.py       Контроль характеристик окон
verify_attack.py           Проверка адресов в выбранном периоде
src/pcap_2s_windows.py     Формирование временных окон из пакетов
src/detectors.py           Пять детекторов
tests/test_pipeline.py     Проверки агрегации и алгоритмов
```

Результаты автоматически сохраняются в `results/`, рассчитанные признаки — в `data/processed/`. Эти каталоги, исходные PCAP и `.venv/` исключены через `.gitignore`.

## Методические ограничения

Данные размечаются по времени сценария CIC-IDS2017; для уточнённой оценки первого/последнего атакующего пакета используется [независимый разбор захвата](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html). Результаты относятся к **одному эпизоду DDoS**. Выбор параметров на нём не является независимой валидацией. Задержка рассчитывается по времени завершения двухсекундного окна; задержка реального захвата, обработки и сетевого оповещения отдельно не измерялась.
