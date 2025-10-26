import nodemailer from 'nodemailer';

interface SendEmailOptions {
  email: string;
  subject: string;
  text: string;
  html?: string;
}

export const sendEmail = async (options: SendEmailOptions) => {
  // 1) Create a transporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_SERVER_HOST,
    port: parseInt(process.env.EMAIL_SERVER_PORT || '587'),
    auth: {
      user: process.env.EMAIL_SERVER_USER,
      pass: process.env.EMAIL_SERVER_PASSWORD,
    },
    secure: false, // true for 465, false for other ports like 587
    tls: {
      rejectUnauthorized: false,
    },
  });

  // 2) Define the email options
  const mailOptions = {
    from: process.env.EMAIL_FROM || `"Skillyug" <${process.env.EMAIL_SERVER_USER}>`,
    to: options.email,
    subject: options.subject,
    text: options.text,
    html: options.html, // For HTML emails
  };

  // 3) Actually send the email
  await transporter.sendMail(mailOptions);
};
