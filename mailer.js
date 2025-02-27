const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'irisj.cruz.clemente.ce23@gmail.com',
        pass: 'alqqygztlcnrypko',
    },
});

const sendResetEmail = async (correo, resetCode) => {
    const mailOptions = {
        from: 'irisj.cruz.clemente.ce23@gmail.com',
        to: correo,
        subject: 'Código de Recuperación de Contraseña',
        text: `Tu código de recuperación es: ${resetCode}`,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Correo de recuperación enviado');
    } catch (error) {
        console.error('Error al enviar el correo:', error);
    }
};

// Asegúrate de exportar la función
module.exports = { sendResetEmail };