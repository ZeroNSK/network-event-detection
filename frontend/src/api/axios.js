import axios from 'axios';
import { toast } from 'react-toastify';

const getApiBaseURL = () => {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }

  return `${window.location.protocol}//${window.location.hostname}:8000/api`;
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
    if (error.response?.status === 401) {
      // При ошибке авторизации очищаем сессию и возвращаем на страницу входа.
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    } else if (error.response?.status === 403) {
      // При запрете доступа показываем уведомление.
      toast.error('Недостаточно прав для выполнения этой операции');
    }
    return Promise.reject(error);
  }
);

export default api;
