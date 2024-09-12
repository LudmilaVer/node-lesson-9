import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Sequelize, DataTypes } from 'sequelize';

const app = express();
app.use(express.json());

// Подключение к MySQL
const sequelize = new Sequelize('database_development', 'root', '1449913luda', {
    host: 'localhost',
    dialect: 'mysql',
    port: 3306
});

// Модель пользователя
const User = sequelize.define('User', {
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    role: {
        type: DataTypes.STRING,
        defaultValue: 'user'
    },
    mustChangePassword: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    }
}, {
    tableName: 'users'
});

// Middleware для авторизации
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).send('Нет токена, авторизация отклонена');
    }

    try {
        const decoded = jwt.verify(token, 'secret');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).send('Токен недействителен');
    }
};

// Роут регистрации пользователя
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    // Проверяем, существует ли пользователь
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
        return res.status(400).send('Email уже зарегистрирован');
    }

    // Хэшируем пароль
    const hashedPassword = await bcrypt.hash(password, 10);

    // Создаем нового пользователя
    const newUser = await User.create({
        email,
        password: hashedPassword
    });

    res.status(201).send('Пользователь успешно зарегистрирован');
});

// Роут смены пароля
app.post('/change-password', authMiddleware, async (req, res) => {
    const { newPassword } = req.body;

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.update(
        { password: hashedPassword, mustChangePassword: false },
        { where: { id: req.user.id } }
    );

    res.status(200).send('Пароль успешно обновлен');
});

// Роут удаления аккаунта
app.post('/delete-account', authMiddleware, async (req, res) => {
    const { password } = req.body;

    const user = await User.findByPk(req.user._id);

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).send('Неверный пароль');
    }

    await User.destroy({ where: { id: req.user._id } });

    res.status(200).send('Аккаунт успешно удален');
});

// Роут для администраторов
app.get('/admin', authMiddleware, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Доступ запрещен');
    }
    res.status(200).json({ message: 'Добро пожаловать, администратор' });
});

// Подключение к базе данных и запуск сервера
const PORT = process.env.PORT || 4000;

sequelize.sync().then(() => {
    app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
}).catch((err) => {
    console.error('Ошибка подключения к базе данных:', err);
});
