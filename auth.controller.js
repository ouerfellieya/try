const db = require('../models');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = db.User;
const SECRET = 'jwt-secret-key'; // ⚠️ À déplacer dans un fichier .env et charger avec dotenv

// Affiche le formulaire de login
exports.loginForm = (req, res) => {
  res.render('login', { error: null });
};

// Gère la connexion de l'utilisateur
exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.render('login', { error: 'Utilisateur non trouvé.' });
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.render('login', { error: 'Mot de passe incorrect.' });
    }

    const token = jwt.sign(
      { id: user.id, 
        username: user.username, 
        fullname: user.fullname, 
        email: user.email,
        brandName: user.brandName,
        createdAt: user.createdAt,
        password: user.password,
     role: user.role },
      SECRET,
      { expiresIn: '1h' }
    );

    const userId = user.id;

    // Nécessite cookie-parser (middleware à ajouter dans app.js)
    res.cookie('token', token);

    if (user.role === 'gestionnaire') {
      return res.redirect(`/products/my-products?userId=${userId}`); // tableau de bord gestionnaire
    } else if (user.role === 'admin') {
      return res.redirect(`/products/admin?userId=${userId}`); // tableau de bord admin (à créer)
    } else {
      return res.redirect(`/products/client?userId=${userId}`); // tableau de bord client (à créer)
    }


  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Erreur serveur.' });
  }
};

// Affiche le formulaire d'inscription
exports.registerForm = (req, res) => {
  res.render('register', { error: null });
};

// Gère l'inscription d'un utilisateur
exports.registerUser = async (req, res) => {
  const { name, fullname, username, email, password, isManager, brandName } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      name,
      fullname,
      username,
      email,
      password: hashedPassword,
      role: isManager === 'on' ? 'gestionnaire' : 'client',
      brandName: isManager === 'on' ? brandName : null
    });

    res.redirect('/auth/login');
  } catch (err) {
    console.error(err);
    res.render('register', { error: 'Erreur lors de l’inscription.' });
  }
};
