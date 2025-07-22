import React, { useState, useEffect, createContext, useContext } from 'react';
import axios from 'axios';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchCurrentUser();
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchCurrentUser = async () => {
    try {
      const response = await axios.get(`${API}/auth/me`);
      setUser(response.data);
    } catch (error) {
      console.error('Error fetching user:', error);
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    const response = await axios.post(`${API}/auth/login`, { email, password });
    const { access_token, user: userData } = response.data;
    
    localStorage.setItem('token', access_token);
    setToken(access_token);
    setUser(userData);
    axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
    
    return userData;
  };

  const register = async (name, email, password, role = 'user') => {
    const response = await axios.post(`${API}/auth/register`, { name, email, password, role });
    const { access_token, user: userData } = response.data;
    
    localStorage.setItem('token', access_token);
    setToken(access_token);
    setUser(userData);
    axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
    
    return userData;
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    delete axios.defaults.headers.common['Authorization'];
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Auth Components
const AuthForm = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    role: 'user'
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, register } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isLogin) {
        await login(formData.email, formData.password);
      } else {
        await register(formData.name, formData.email, formData.password, formData.role);
      }
    } catch (error) {
      setError(error.response?.data?.detail || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            {isLogin ? 'Entre na sua conta' : 'Criar nova conta'}
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            CRM Kanban - Simplifique sua gestão de leads
          </p>
        </div>
        <form className="mt-8 space-y-6 bg-white p-8 rounded-lg shadow-lg" onSubmit={handleSubmit}>
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          )}
          
          <div className="space-y-4">
            {!isLogin && (
              <input
                type="text"
                required
                placeholder="Nome completo"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-gray-900"
              />
            )}
            
            <input
              type="email"
              required
              placeholder="Email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-gray-900"
            />
            
            <input
              type="password"
              required
              placeholder="Senha"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-gray-900"
            />
            
            {!isLogin && (
              <select
                value={formData.role}
                onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-gray-900"
              >
                <option value="user">Usuário</option>
                <option value="manager">Gerente</option>
                <option value="admin">Administrador</option>
              </select>
            )}
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-3 px-4 rounded-lg hover:from-blue-700 hover:to-indigo-700 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all duration-200 font-medium disabled:opacity-50"
          >
            {loading ? 'Processando...' : (isLogin ? 'Entrar' : 'Registrar')}
          </button>

          <div className="text-center">
            <button
              type="button"
              onClick={() => setIsLogin(!isLogin)}
              className="text-blue-600 hover:text-blue-700 font-medium"
            >
              {isLogin ? 'Não tem conta? Registre-se' : 'Já tem conta? Entre'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Stats Card Component
const StatsCard = ({ title, value, icon, color, subtitle }) => (
  <div className="bg-white rounded-lg p-6 shadow-lg border border-gray-100">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-gray-600 mb-1">{title}</p>
        <p className={`text-2xl font-bold ${color}`}>{value}</p>
        {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
      </div>
      <div className={`text-3xl ${color}`}>
        {icon}
      </div>
    </div>
  </div>
);

// Dashboard Component
const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardStats();
  }, []);

  const fetchDashboardStats = async () => {
    try {
      const response = await axios.get(`${API}/dashboard/stats`);
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="bg-gray-200 h-24 rounded-lg"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const formatCurrency = (value) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL'
    }).format(value);
  };

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Dashboard</h2>
        <p className="text-gray-600">Visão geral dos seus leads e performance</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatsCard
          title="Total de Leads"
          value={stats?.total_leads || 0}
          icon="👥"
          color="text-blue-600"
          subtitle="leads ativos"
        />
        <StatsCard
          title="Taxa de Conversão"
          value={`${stats?.conversion_rate || 0}%`}
          icon="📈"
          color="text-green-600"
          subtitle="fechamentos ganhos"
        />
        <StatsCard
          title="Ticket Médio"
          value={formatCurrency(stats?.avg_deal_size || 0)}
          icon="💰"
          color="text-yellow-600"
          subtitle="por lead fechado"
        />
        <StatsCard
          title="Pipeline Valor"
          value={formatCurrency(
            Object.values(stats?.status_stats || {}).reduce(
              (sum, stat) => sum + (stat.value || 0), 0
            )
          )}
          icon="🎯"
          color="text-purple-600"
          subtitle="valor total em pipeline"
        />
      </div>

      {/* Status Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="bg-white rounded-lg p-6 shadow-lg">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Distribuição por Status</h3>
          <div className="space-y-3">
            {stats?.status_stats && Object.entries(stats.status_stats).map(([status, data]) => {
              const statusLabels = {
                'novo': 'Novo',
                'qualificado': 'Qualificado',
                'proposta': 'Proposta',
                'negociacao': 'Negociação',
                'fechado_ganho': 'Fechado (Ganho)',
                'fechado_perdido': 'Fechado (Perdido)'
              };
              
              const colors = {
                'novo': 'bg-blue-500',
                'qualificado': 'bg-green-500',
                'proposta': 'bg-yellow-500',
                'negociacao': 'bg-red-500',
                'fechado_ganho': 'bg-green-600',
                'fechado_perdido': 'bg-gray-500'
              };

              return (
                <div key={status} className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className={`w-3 h-3 rounded-full ${colors[status]} mr-3`}></div>
                    <span className="text-sm text-gray-700">{statusLabels[status]}</span>
                  </div>
                  <div className="flex items-center space-x-4">
                    <span className="text-sm font-medium text-gray-900">
                      {data.count} leads
                    </span>
                    <span className="text-sm text-gray-600">
                      {formatCurrency(data.value || 0)}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="bg-white rounded-lg p-6 shadow-lg">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Atividades Recentes</h3>
          <div className="space-y-3 max-h-64 overflow-y-auto">
            {stats?.recent_activities?.slice(0, 8).map((activity, index) => (
              <div key={index} className="flex items-start space-x-3 p-2 hover:bg-gray-50 rounded">
                <div className="flex-shrink-0 w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-gray-900 truncate">
                    {activity.details}
                  </p>
                  <p className="text-xs text-gray-500">
                    {new Date(activity.timestamp).toLocaleString('pt-BR')}
                  </p>
                </div>
              </div>
            )) || (
              <p className="text-gray-500 text-sm">Nenhuma atividade recente</p>
            )}
          </div>
        </div>
      </div>

      {/* Top Sources */}
      {stats?.top_sources?.length > 0 && (
        <div className="bg-white rounded-lg p-6 shadow-lg">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Fontes de Leads</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
            {stats.top_sources.map((source, index) => (
              <div key={index} className="text-center p-4 border border-gray-200 rounded-lg">
                <p className="font-medium text-gray-900">{source._id || 'Não informado'}</p>
                <p className="text-sm text-gray-600">{source.count} leads</p>
                <p className="text-sm text-green-600">{formatCurrency(source.total_value || 0)}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Calendar Component
const Calendar = () => {
  const [events, setEvents] = useState([]);
  const [showEventForm, setShowEventForm] = useState(false);
  const [googleConnected, setGoogleConnected] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCalendarEvents();
  }, []);

  const fetchCalendarEvents = async () => {
    try {
      const response = await axios.get(`${API}/calendar/events`);
      setEvents(response.data);
    } catch (error) {
      console.error('Error fetching calendar events:', error);
    } finally {
      setLoading(false);
    }
  };

  const connectGoogleCalendar = async () => {
    try {
      const response = await axios.get(`${API}/auth/google/connect`);
      window.open(response.data.authorization_url, '_blank');
    } catch (error) {
      console.error('Error connecting Google Calendar:', error);
    }
  };

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      <div className="mb-8 flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Calendário</h2>
          <p className="text-gray-600">Gerencie seus eventos e follow-ups</p>
        </div>
        <div className="space-x-3">
          {!googleConnected && (
            <button
              onClick={connectGoogleCalendar}
              className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
            >
              📅 Conectar Google Calendar
            </button>
          )}
          <button
            onClick={() => setShowEventForm(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            ➕ Novo Evento
            </button>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-lg">
        <div className="p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Próximos Eventos</h3>
          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="animate-pulse bg-gray-200 h-16 rounded"></div>
              ))}
            </div>
          ) : events.length > 0 ? (
            <div className="space-y-4">
              {events.map((event) => (
                <div key={event.id} className="border-l-4 border-blue-500 pl-4 py-3 bg-blue-50 rounded-r">
                  <h4 className="font-medium text-gray-900">{event.title}</h4>
                  <p className="text-sm text-gray-600">{event.description}</p>
                  <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                    <span>📅 {new Date(event.start_time).toLocaleDateString('pt-BR')}</span>
                    <span>🕐 {new Date(event.start_time).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}</span>
                    <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded-full text-xs">
                      {event.event_type}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <p className="text-gray-500">Nenhum evento agendado</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Kanban Components (existing code remains the same)
const LeadCard = ({ lead, onDragStart }) => {
  const formatCurrency = (value) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL'
    }).format(value);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('pt-BR');
  };

  const priorityColors = {
    high: 'border-red-500 bg-red-50',
    medium: 'border-yellow-500 bg-yellow-50',
    low: 'border-green-500 bg-green-50'
  };

  return (
    <div
      draggable
      onDragStart={(e) => onDragStart(e, lead)}
      className={`bg-white rounded-lg shadow-md p-4 mb-3 cursor-move hover:shadow-lg transition-all duration-200 border-l-4 ${priorityColors[lead.priority] || 'border-blue-500'}`}
    >
      <div className="flex justify-between items-start mb-2">
        <h4 className="font-semibold text-gray-900 text-sm">{lead.title}</h4>
        {lead.priority === 'high' && <span className="text-red-500 text-xs">🔴</span>}
      </div>
      
      {lead.company && (
        <p className="text-sm text-gray-600 mb-1">🏢 {lead.company}</p>
      )}
      {lead.contact_name && (
        <p className="text-sm text-gray-600 mb-1">👤 {lead.contact_name}</p>
      )}
      {lead.email && (
        <p className="text-sm text-blue-600 mb-1">📧 {lead.email}</p>
      )}
      {lead.value > 0 && (
        <p className="text-sm font-semibold text-green-600 mb-1">
          💰 {formatCurrency(lead.value)}
        </p>
      )}
      
      {lead.next_follow_up && (
        <p className="text-xs text-orange-600 mb-2">
          🔔 Follow-up: {formatDate(lead.next_follow_up)}
        </p>
      )}
      
      {lead.tags && lead.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {lead.tags.slice(0, 3).map((tag, index) => (
            <span
              key={index}
              className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full"
            >
              {tag}
            </span>
          ))}
          {lead.tags.length > 3 && (
            <span className="text-xs text-gray-500">+{lead.tags.length - 3}</span>
          )}
        </div>
      )}
      
      <div className="flex justify-between items-center text-xs text-gray-500 mt-2">
        <span>{formatDate(lead.created_at)}</span>
        <div className="flex items-center space-x-1">
          {lead.source && (
            <span className="bg-gray-100 px-2 py-1 rounded text-xs">{lead.source}</span>
          )}
          {lead.assigned_to && (
            <span className="bg-gray-100 px-2 py-1 rounded">👤</span>
          )}
        </div>
      </div>
    </div>
  );
};

const KanbanColumn = ({ column, onDrop, onDragOver }) => {
  const totalValue = column.leads.reduce((sum, lead) => sum + (lead.value || 0), 0);
  
  const formatCurrency = (value) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL'
    }).format(value);
  };

  return (
    <div
      className="bg-gray-50 rounded-lg p-4 min-h-96 min-w-80 border border-gray-200"
      onDrop={(e) => onDrop(e, column.status)}
      onDragOver={onDragOver}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <h3 className="font-bold text-lg text-gray-800">{column.title}</h3>
          <span
            className="w-4 h-4 rounded-full"
            style={{ backgroundColor: column.color }}
          ></span>
        </div>
        <span className="text-sm font-medium text-gray-600">
          {column.leads.length}
        </span>
      </div>
      
      <div className="space-y-3 max-h-96 overflow-y-auto">
        {column.leads.map((lead) => (
          <LeadCard
            key={lead.id}
            lead={lead}
            onDragStart={(e, lead) => {
              e.dataTransfer.setData('text/plain', JSON.stringify(lead));
            }}
          />
        ))}
      </div>
      
      <div className="text-sm text-gray-500 mt-4 pt-2 border-t border-gray-200">
        <div className="flex justify-between">
          <span>{column.leads.length} lead{column.leads.length !== 1 ? 's' : ''}</span>
          {totalValue > 0 && (
            <span className="text-green-600 font-medium">
              {formatCurrency(totalValue)}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

const NewLeadForm = ({ onClose, onSubmit }) => {
  const [formData, setFormData] = useState({
    title: '',
    company: '',
    contact_name: '',
    email: '',
    phone: '',
    status: 'novo',
    tags: '',
    notes: '',
    value: '',
    priority: 'medium',
    assigned_to: '',
    source: '',
    next_follow_up: '',
    expected_close_date: ''
  });
  
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const leadData = {
        ...formData,
        tags: formData.tags ? formData.tags.split(',').map(tag => tag.trim()) : [],
        value: parseFloat(formData.value) || 0,
        next_follow_up: formData.next_follow_up ? new Date(formData.next_follow_up).toISOString() : null,
        expected_close_date: formData.expected_close_date ? new Date(formData.expected_close_date).toISOString() : null
      };
      await onSubmit(leadData);
      onClose();
    } catch (error) {
      console.error('Error creating lead:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-4xl max-h-96 overflow-y-auto m-4">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-bold text-gray-900">Novo Lead</h3>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-700 text-xl"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Título *
              </label>
              <input
                type="text"
                required
                value={formData.title}
                onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Empresa
              </label>
              <input
                type="text"
                value={formData.company}
                onChange={(e) => setFormData({ ...formData, company: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Nome do Contato
              </label>
              <input
                type="text"
                value={formData.contact_name}
                onChange={(e) => setFormData({ ...formData, contact_name: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Telefone
              </label>
              <input
                type="text"
                value={formData.phone}
                onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Valor (R$)
              </label>
              <input
                type="number"
                step="0.01"
                value={formData.value}
                onChange={(e) => setFormData({ ...formData, value: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Prioridade
              </label>
              <select
                value={formData.priority}
                onChange={(e) => setFormData({ ...formData, priority: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              >
                <option value="low">Baixa</option>
                <option value="medium">Média</option>
                <option value="high">Alta</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Fonte
              </label>
              <input
                type="text"
                value={formData.source}
                onChange={(e) => setFormData({ ...formData, source: e.target.value })}
                placeholder="website, referral, cold_call..."
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Próximo Follow-up
              </label>
              <input
                type="datetime-local"
                value={formData.next_follow_up}
                onChange={(e) => setFormData({ ...formData, next_follow_up: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Tags (separadas por vírgula)
              </label>
              <input
                type="text"
                value={formData.tags}
                onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                placeholder="marketing, urgente, vip"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Data Esperada de Fechamento
              </label>
              <input
                type="date"
                value={formData.expected_close_date}
                onChange={(e) => setFormData({ ...formData, expected_close_date: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>

            <div className="md:col-span-3">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Observações
              </label>
              <textarea
                value={formData.notes}
                onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                rows="3"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900"
              />
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4 border-t">
            <button
              type="button"
              onClick={onClose}
              className="px-6 py-2 text-gray-600 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {loading ? 'Salvando...' : 'Criar Lead'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const KanbanBoard = () => {
  const [kanbanData, setKanbanData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showNewLeadForm, setShowNewLeadForm] = useState(false);
  const { user } = useAuth();

  useEffect(() => {
    fetchKanbanData();
  }, []);

  const fetchKanbanData = async () => {
    try {
      const response = await axios.get(`${API}/kanban`);
      setKanbanData(response.data);
    } catch (error) {
      console.error('Error fetching kanban data:', error);
    } finally {
      setLoading(false);
    }
  };

  const createLead = async (leadData) => {
    try {
      await axios.post(`${API}/leads`, leadData);
      fetchKanbanData(); // Refresh the board
    } catch (error) {
      console.error('Error creating lead:', error);
      throw error;
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const handleDrop = async (e, newStatus) => {
    e.preventDefault();
    const leadData = JSON.parse(e.dataTransfer.getData('text/plain'));
    
    if (leadData.status === newStatus) {
      return; // No change needed
    }

    try {
      await axios.post(`${API}/kanban/move`, {
        lead_id: leadData.id,
        new_status: newStatus,
        new_position: 0
      });
      fetchKanbanData(); // Refresh the board
    } catch (error) {
      console.error('Error moving lead:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-xl">Carregando...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Kanban Board */}
      <div className="p-6">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Pipeline de Vendas</h1>
            <p className="text-gray-600">Gerencie seus leads através do funil de vendas</p>
          </div>
          <button
            onClick={() => setShowNewLeadForm(true)}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2 transition-colors"
          >
            ➕ Novo Lead
          </button>
        </div>

        <div className="flex gap-6 overflow-x-auto pb-4">
          {kanbanData.map((column) => (
            <KanbanColumn
              key={column.status}
              column={column}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
            />
          ))}
        </div>
      </div>

      {/* New Lead Form Modal */}
      {showNewLeadForm && (
        <NewLeadForm
          onClose={() => setShowNewLeadForm(false)}
          onSubmit={createLead}
        />
      )}
    </div>
  );
};

// Main Dashboard Component with Navigation
const MainDashboard = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const { logout, user } = useAuth();

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊' },
    { id: 'kanban', label: 'Kanban', icon: '📋' },
    { id: 'calendar', label: 'Calendário', icon: '📅' },
  ];

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard />;
      case 'kanban':
        return <KanbanBoard />;
      case 'calendar':
        return <Calendar />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-8">
              <div>
                <h1 className="text-xl font-bold text-gray-900">CRM Kanban</h1>
                <p className="text-sm text-gray-600">Bem-vindo, {user?.name}!</p>
              </div>
              <nav className="flex space-x-1">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                      activeTab === tab.id
                        ? 'bg-blue-100 text-blue-700 border-b-2 border-blue-600'
                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                    }`}
                  >
                    <span>{tab.icon}</span>
                    <span>{tab.label}</span>
                  </button>
                ))}
              </nav>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-sm text-gray-600">
                <span className="font-medium capitalize">{user?.role}</span>
              </div>
              <button
                onClick={logout}
                className="text-gray-600 hover:text-gray-900 px-3 py-2 rounded-lg hover:bg-gray-100 transition-colors"
              >
                Sair
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <main>{renderContent()}</main>
    </div>
  );
};

// Main App Component
function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="text-center">
          <div className="loading-spinner mx-auto mb-4"></div>
          <p className="text-gray-600">Carregando...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="App">
      {user ? <MainDashboard /> : <AuthForm />}
    </div>
  );
}

// Root App with AuthProvider
export default function RootApp() {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
}

