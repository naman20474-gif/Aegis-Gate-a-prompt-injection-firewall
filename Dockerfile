FROM node:20.18.1-bookworm-slim AS frontend-build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY frontend ./frontend
COPY tsconfig.json vite.config.ts tailwind.config.js postcss.config.js ./
RUN npm run build

FROM python:3.11.2-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AEGIS_SERVE_FRONTEND=true
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY backend ./backend
COPY pyproject.toml ./
COPY --from=frontend-build /src/dist ./dist
EXPOSE 8000
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
