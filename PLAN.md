# Полный план обучения Python — от нуля до Senior
# Проект: AWPassword Manager

---

## 📍 ГДЕ ТЫ СЕЙЧАС
Ты находишься между Junior и Middle.
Пройдено: основы Python, ООП, Flask, REST API, JS, Git, тесты, шифрование.
Следующий шаг: база данных → авторизация → архитектура → деплой.

---

## ✅ Уже пройдено
- [x] Модули и импорты
- [x] Функции, return, параметры, *args, **kwargs
- [x] Списки, словари, методы (append, copy, clear, update)
- [x] Классы, __init__, self, инкапсуляция
- [x] Исключения (try/except, ValueError, конкретные типы ошибок)
- [x] Работа с файлами (open, with, JSON)
- [x] Декораторы (создание и применение)
- [x] datetime, uuid
- [x] Тестирование (unittest, setUp, assertEqual, assertRaises)
- [x] Шифрование (cryptography, Fernet)
- [x] tkinter GUI (Label, Entry, Button, Scale, Toplevel, StringVar)
- [x] Flask (routes, render_template, jsonify, request)
- [x] REST API (GET, POST, DELETE, PUT)
- [x] HTML/CSS/JavaScript основы
- [x] fetch API (async/await JS)
- [x] Git, .gitignore
- [x] PyInstaller (.exe)
- [x] Поиск, удаление, редактирование записей
- [x] UUID идентификаторы
- [x] Разделение на модули (core, ui, app)

---

## 🟡 УРОВЕНЬ: JUNIOR
### Приоритет: ВЫСОКИЙ — без этого нельзя двигаться дальше

#### Этап 1: Углубление Python (2-3 недели)
**Критически важно:**
- [ ] Строки — все методы (split, join, strip, replace, startswith, endswith)
- [ ] List/dict/set comprehensions (однострочные циклы)
- [ ] lambda функции
- [ ] map(), filter(), sorted() с key=
- [ ] Область видимости (LEGB — Local, Enclosing, Global, Built-in)
- [ ] Итераторы и генераторы (yield, next, iter)
- [ ] Контекстные менеджеры (with, __enter__, __exit__)
- [ ] Модули и пакеты (создание своего пакета, __init__.py)

**Важно:**
- [ ] Регулярные выражения (re — search, match, findall, sub)
- [ ] Работа с файловой системой (os, pathlib)
- [ ] Работа с переменными окружения (os.environ, python-dotenv)
- [ ] Форматирование строк (f-strings продвинутые, format)
- [ ] Сортировка (sorted, key, reverse, itemgetter)
- [ ] Копирование объектов (copy, deepcopy)
- [ ] Распаковка (*, **)

**Полезно знать:**
- [ ] collections (Counter, defaultdict, OrderedDict, namedtuple)
- [ ] itertools (chain, product, combinations, permutations)
- [ ] functools (partial, reduce, lru_cache)
- [ ] enum (Enum, IntEnum)

#### Этап 2: ООП углубление (2 недели)
**Критически важно:**
- [ ] Наследование (super(), переопределение методов)
- [ ] Магические методы (__str__, __repr__, __len__, __eq__, __hash__, __contains__)
- [ ] @property (геттеры и сеттеры)
- [ ] @classmethod и @staticmethod
- [ ] Type hints (typing — List, Dict, Optional, Union, Tuple, Any)
- [ ] Dataclasses (@dataclass, field, frozen)

**Важно:**
- [ ] Множественное наследование (MRO — Method Resolution Order)
- [ ] Абстрактные классы (ABC, abstractmethod)
- [ ] Протоколы (Protocol — duck typing)
- [ ] __slots__ (оптимизация памяти)
- [ ] Метаклассы (базовое понимание)

**Полезно знать:**
- [ ] Дескрипторы (__get__, __set__, __delete__)
- [ ] __init_subclass__
- [ ] Generic типы

#### Этап 3: База данных (3 недели) ← СЛЕДУЮЩИЙ ШАГ
**Критически важно:**
- [ ] Основы SQL (SELECT, INSERT, UPDATE, DELETE)
- [ ] WHERE, ORDER BY, LIMIT, OFFSET
- [ ] JOIN (INNER, LEFT, RIGHT)
- [ ] Агрегатные функции (COUNT, SUM, AVG, MAX, MIN)
- [ ] SQLite в Python (sqlite3 — cursor, execute, fetchall)
- [ ] Замена JSON на SQLite в PasswordManager
- [ ] Индексы — зачем и когда

**Важно:**
- [ ] GROUP BY, HAVING
- [ ] Подзапросы
- [ ] Транзакции (BEGIN, COMMIT, ROLLBACK)
- [ ] SQLAlchemy Core (engine, connection, text)
- [ ] SQLAlchemy ORM (модели, сессии, запросы)
- [ ] Alembic — миграции базы данных

**Полезно знать:**
- [ ] PostgreSQL отличия от SQLite
- [ ] Нормализация БД (1NF, 2NF, 3NF)
- [ ] N+1 проблема и как решать
- [ ] Explain/Analyze запросов

#### Этап 4: Веб разработка продвинутая (3 недели)
**Критически важно:**
- [ ] HTTP протокол (методы, статусы, заголовки, body)
- [ ] Flask Blueprints (разделение routes на модули)
- [ ] Flask middleware и error handlers
- [ ] FastAPI основы (async routes, Pydantic модели)
- [ ] Pydantic (валидация данных, схемы)
- [ ] REST API дизайн (версионирование /api/v1/, пагинация)
- [ ] Авторизация — bcrypt хэширование паролей
- [ ] JWT токены (создание, верификация, refresh)

**Важно:**
- [ ] Flask-Login (сессии пользователей)
- [ ] CORS (Cross-Origin Resource Sharing)
- [ ] Rate limiting (flask-limiter)
- [ ] Middleware для логирования запросов
- [ ] Swagger/OpenAPI документация (FastAPI автогенерация)
- [ ] Cookies и сессии

**Полезно знать:**
- [ ] WebSockets основы
- [ ] Server-Sent Events
- [ ] GraphQL основы

#### Этап 5: Тестирование (2 недели)
**Критически важно:**
- [ ] pytest (fixtures, parametrize, marks, conftest)
- [ ] Mock и patch (unittest.mock)
- [ ] Тестирование Flask/FastAPI (TestClient)
- [ ] Coverage (покрытие кода — цель 80%+)

**Важно:**
- [ ] Фикстуры с областью видимости (scope)
- [ ] Параметризованные тесты
- [ ] Тестирование БД (in-memory SQLite)
- [ ] TDD — разработка через тесты
- [ ] Интеграционные тесты vs юнит тесты

**Полезно знать:**
- [ ] Property-based testing (hypothesis)
- [ ] Snapshot тестирование
- [ ] Нагрузочное тестирование (locust)

---

## 🟠 УРОВЕНЬ: MIDDLE
### Приоритет: ВЫСОКИЙ — это отличает Junior от Middle

#### Этап 6: Асинхронное программирование (2 недели)
**Критически важно:**
- [ ] asyncio (event loop, coroutines, tasks, gather)
- [ ] async/await углубление
- [ ] Разница между threading, multiprocessing, asyncio
- [ ] aiohttp (асинхронные HTTP запросы)
- [ ] Асинхронный FastAPI

**Важно:**
- [ ] asyncpg (асинхронная работа с PostgreSQL)
- [ ] aiosqlite
- [ ] Семафоры и локи в asyncio
- [ ] Celery (фоновые задачи)
- [ ] Redis как брокер для Celery

**Полезно знать:**
- [ ] Trio (альтернатива asyncio)
- [ ] uvloop (ускорение event loop)

#### Этап 7: Архитектура (3 недели)
**Критически важно:**
- [ ] SOLID принципы (S, O, L, I, D — с примерами)
- [ ] DRY, KISS, YAGNI
- [ ] Repository pattern (отделение БД от бизнес-логики)
- [ ] Service layer pattern
- [ ] Dependency Injection
- [ ] Clean Architecture (слои: domain, application, infrastructure)

**Важно:**
- [ ] Design patterns: Factory, Singleton, Observer, Strategy, Decorator
- [ ] Разделение на слои в нашем проекте
- [ ] Hexagonal Architecture (Ports and Adapters)
- [ ] Микросервисы — основы и когда применять

**Полезно знать:**
- [ ] Event-driven architecture
- [ ] CQRS (Command Query Responsibility Segregation)
- [ ] Domain-Driven Design основы

#### Этап 8: DevOps основы (3 недели)
**Критически важно:**
- [ ] Linux команды (bash, ssh, права доступа, процессы)
- [ ] Docker (Dockerfile, образы, контейнеры, volumes)
- [ ] Docker Compose (многоконтейнерные приложения)
- [ ] Переменные окружения в Docker (.env файлы)
- [ ] GitHub Actions (автотесты при push)

**Важно:**
- [ ] Nginx (reverse proxy, статика, SSL)
- [ ] Certbot (бесплатные SSL сертификаты)
- [ ] Деплой на VPS (Railway, Render, DigitalOcean)
- [ ] CI/CD пайплайн (тесты → сборка → деплой)
- [ ] Логирование в production (structlog, loguru)

**Полезно знать:**
- [ ] Kubernetes основы (pods, deployments, services)
- [ ] Terraform основы
- [ ] Ansible основы

#### Этап 9: Фронтенд (4 недели)
**Критически важно:**
- [ ] JavaScript ES6+ (классы, модули, деструктуризация, spread, Promise)
- [ ] TypeScript основы (типы, интерфейсы, generics)
- [ ] React (компоненты, props, state, JSX)
- [ ] React hooks (useState, useEffect, useRef, useCallback, useMemo)
- [ ] React Router (навигация между страницами)
- [ ] Axios для API запросов

**Важно:**
- [ ] useContext (глобальное состояние)
- [ ] Custom hooks
- [ ] Tailwind CSS
- [ ] Vite (сборщик)
- [ ] React Query (кэширование запросов)
- [ ] Формы (react-hook-form)

**Полезно знать:**
- [ ] Redux Toolkit (сложное состояние)
- [ ] Next.js (SSR, SSG)
- [ ] Storybook (документация компонентов)

#### Этап 10: Безопасность (2 недели)
**Критически важно:**
- [ ] OWASP Top 10 (основные уязвимости веб-приложений)
- [ ] SQL инъекции и защита (параметризованные запросы)
- [ ] XSS (Cross-Site Scripting) и защита
- [ ] CSRF защита (токены)
- [ ] Хэширование паролей (bcrypt, argon2)
- [ ] Безопасное хранение секретов (.env, никогда в git)

**Важно:**
- [ ] Rate limiting (защита от брутфорса)
- [ ] HTTPS и TLS
- [ ] Заголовки безопасности (CSP, HSTS, X-Frame-Options)
- [ ] Валидация и санитизация входных данных
- [ ] Принцип минимальных привилегий

**Полезно знать:**
- [ ] Penetration testing основы
- [ ] OAuth 2.0 и OpenID Connect
- [ ] Vault для секретов

---

## 🔴 УРОВЕНЬ: SENIOR
### Приоритет: СРЕДНИЙ — строится на крепком Middle фундаменте

#### Этап 11: Производительность (2 недели)
**Критически важно:**
- [ ] Профилирование кода (cProfile, line_profiler, py-spy)
- [ ] Оптимизация запросов к БД (индексы, explain analyze)
- [ ] Кэширование (Redis — стратегии, TTL, инвалидация)
- [ ] N+1 проблема и решения (eager loading)

**Важно:**
- [ ] Memory profiling (tracemalloc, memory_profiler)
- [ ] GIL (Global Interpreter Lock) — понимание ограничений
- [ ] multiprocessing для CPU-bound задач
- [ ] threading для I/O-bound задач
- [ ] Пагинация и курсорная пагинация

**Полезно знать:**
- [ ] Cython (ускорение Python кода)
- [ ] NumPy для числовых вычислений
- [ ] Connection pooling

#### Этап 12: Мониторинг и наблюдаемость (2 недели)
**Критически важно:**
- [ ] Структурированное логирование (loguru, structlog)
- [ ] Уровни логов (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- [ ] Метрики приложения (Prometheus + Grafana)
- [ ] Health check endpoints (/health, /ready)

**Важно:**
- [ ] Sentry (отслеживание ошибок в production)
- [ ] Distributed tracing (OpenTelemetry)
- [ ] Алерты (когда что-то сломалось)
- [ ] ELK Stack основы (Elasticsearch, Logstash, Kibana)

**Полезно знать:**
- [ ] Jaeger (трейсинг)
- [ ] Datadog / New Relic

#### Этап 13: Продвинутая архитектура (3 недели)
**Критически важно:**
- [ ] Очереди сообщений (Redis Pub/Sub, RabbitMQ основы)
- [ ] API Gateway паттерн
- [ ] Версионирование API
- [ ] Backward compatibility

**Важно:**
- [ ] Event Sourcing основы
- [ ] Saga pattern (распределённые транзакции)
- [ ] Circuit Breaker pattern
- [ ] Kafka основы

**Полезно знать:**
- [ ] Service mesh (Istio)
- [ ] gRPC

#### Этап 14: Облако (3 недели)
**Критически важно:**
- [ ] AWS основы (EC2, S3, RDS, Lambda, IAM)
- [ ] Kubernetes основы (pods, deployments, services, ingress)
- [ ] Helm (пакетный менеджер для Kubernetes)

**Важно:**
- [ ] Terraform (инфраструктура как код)
- [ ] AWS CDK или Pulumi
- [ ] Serverless основы

**Полезно знать:**
- [ ] GCP или Azure альтернативы
- [ ] Multi-cloud стратегии

#### Этап 15: Лидерство и процессы (постоянно)
**Критически важно:**
- [ ] Code review — как давать конструктивную обратную связь
- [ ] Техдолг — как оценивать и управлять
- [ ] Документация (README, ADR — Architecture Decision Records)
- [ ] Системный дизайн (проектирование масштабируемых систем)

**Важно:**
- [ ] Agile/Scrum/Kanban
- [ ] Оценка задач (story points, t-shirt sizing)
- [ ] Менторинг junior разработчиков
- [ ] Технические интервью (как проходить и проводить)

**Полезно знать:**
- [ ] RFC процесс (Request for Comments)
- [ ] Postmortem культура
- [ ] OKR и технические метрики

---

## 🏆 ФИНАЛЬНЫЙ ПРОЕКТ — Полноценный SaaS
- [ ] FastAPI бэкенд + PostgreSQL + Redis
- [ ] React + TypeScript фронтенд
- [ ] Docker + Docker Compose
- [ ] CI/CD через GitHub Actions
- [ ] Деплой на VPS с Nginx + SSL
- [ ] Авторизация (JWT + bcrypt)
- [ ] Шифрование данных
- [ ] Мониторинг (Sentry + логи)
- [ ] Тесты 80%+ coverage
- [ ] Документация (README + Swagger)

---

## 📊 ОРИЕНТИРОВОЧНЫЕ СРОКИ
| Уровень | Этапы | Время при занятиях каждый день |
|---------|-------|-------------------------------|
| Junior  | 1-5   | 3-4 месяца |
| Middle  | 6-10  | 4-6 месяцев |
| Senior  | 11-15 | 6-12 месяцев |

## 💡 ПРАВИЛА ОБУЧЕНИЯ
1. Каждую тему сразу применяй на проекте
2. Не переходи дальше пока не понял текущее
3. Пиши код руками — не копируй
4. Делай code review своего старого кода
5. Читай чужой код на GitHub
6. Решай задачи на LeetCode (Easy → Medium)
