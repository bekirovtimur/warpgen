// API endpoint для проверки пароля
export default async function handler(req, res) {
    // Разрешаем только POST запросы
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }

    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({ success: false, message: 'Пароль не указан' });
        }

        // Получаем пароли из переменной окружения
        // Формат: JSON массив ["password1", "password2", "password3"]
        // или просто один пароль как строка
        const passwordsEnv = process.env.PASSWORDS;

        if (!passwordsEnv) {
            // Если пароли не настроены, разрешаем доступ (режим разработки)
            return res.json({ success: true });
        }

        let validPasswords = [];

        try {
            // Пробуем распарсить как JSON
            validPasswords = JSON.parse(passwordsEnv);
            if (!Array.isArray(validPasswords)) {
                validPasswords = [validPasswords];
            }
        } catch (e) {
            // Если не JSON, используем как строку
            validPasswords = [passwordsEnv];
        }

        // Проверяем пароль
        const isValid = validPasswords.includes(password);

        if (isValid) {
            return res.json({ success: true });
        } else {
            return res.status(401).json({ success: false, message: 'Неверный пароль' });
        }

    } catch (error) {
        console.error('Auth error:', error);
        return res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
    }
}
