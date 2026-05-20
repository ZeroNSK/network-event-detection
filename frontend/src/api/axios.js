import axios from 'axios';

const getApiBaseURL = () => {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }

  const localHosts = new Set(['localhost', '127.0.0.1']);
  if (localHosts.has(window.location.hostname)) {
    return `${window.location.protocol}//${window.location.hostname}:8000/api`;
  }

  return `${window.location.origin}/api`;
};

const LOCAL_ERROR_ENDPOINTS = new Set([
  '/auth/login',
  '/auth/register',
  '/auth/login-lockout',
]);

const normalizeRequestPath = (url = '') => {
  const path = url.replace(/^https?:\/\/[^/]+/i, '').split('?')[0];
  return path.replace(/^\/api/, '');
};

const shouldUseLocalError = (error) => {
  if (error.config?.skipGlobalErrorPage) {
    return true;
  }

  const requestPath = normalizeRequestPath(error.config?.url);
  return LOCAL_ERROR_ENDPOINTS.has(requestPath);
};

const stringifyDetail = (detail) => {
  if (!detail) {
    return '';
  }

  if (typeof detail === 'string') {
    return detail;
  }

  if (Array.isArray(detail)) {
    const firstError = detail[0];
    if (firstError?.msg) {
      const field = Array.isArray(firstError.loc) ? firstError.loc.join('.') : '';
      return field ? `${field}: ${firstError.msg}` : firstError.msg;
    }
    return 'Ошибка валидации входных данных';
  }

  if (typeof detail === 'object') {
    return detail.message || detail.detail || JSON.stringify(detail);
  }

  return String(detail);
};

const getErrorMessage = (error) => {
  if (!error.response) {
    return 'Сервер недоступен или соединение было прервано';
  }

  const data = error.response.data;
  return (
    stringifyDetail(data?.message) ||
    stringifyDetail(data?.detail) ||
    stringifyDetail(data?.details) ||
    'Произошла ошибка при выполнении запроса'
  );
};

const redirectToErrorPage = (error) => {
  if (typeof window === 'undefined') {
    return;
  }

  if (window.location.pathname === '/error' || window.__apiErrorRedirecting) {
    return;
  }

  const status = error.response?.status || 503;
  const params = new URLSearchParams({
    status: String(status),
    message: getErrorMessage(error),
    from: `${window.location.pathname}${window.location.search}`,
  });

  const code = error.response?.data?.code;
  if (code) {
    params.set('code', code);
  }

  if (status === 401) {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  }

  window.__apiErrorRedirecting = true;
  window.location.assign(`/error?${params.toString()}`);
};

const api = axios.create({
  baseURL: getApiBaseURL(),
  headers: {
    'Content-Type': 'application/json',
  },
});

// Перехватчик запросов добавляет JWT-токен.
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Перехватчик ответов обрабатывает ошибки авторизации.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (!shouldUseLocalError(error)) {
      // Все системные/API-ошибки показываем отдельным экраном, а не только toast/F12.
      redirectToErrorPage(error);
    }
    return Promise.reject(error);
  }
);

export default api;
