-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generación: 13-02-2025 a las 21:32:19
-- Versión del servidor: 10.4.32-MariaDB
-- Versión de PHP: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `sistemariego`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `alertas`
--

CREATE TABLE `alertas` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) DEFAULT NULL,
  `mensaje` text NOT NULL,
  `fecha_alerta` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `alertas`
--

INSERT INTO `alertas` (`id`, `usuario_id`, `mensaje`, `fecha_alerta`) VALUES
(1, 1, 'Humedad baja en Zona A', '2025-01-29 04:15:37'),
(2, 2, 'Temperatura alta en Zona B', '2025-01-29 04:15:37'),
(3, 50, 'Inundación parcial en Zona T', '2025-01-25 08:28:38'),
(4, 97, 'Alerta por rayos en Zona R', '2025-01-19 08:28:38'),
(5, 195, 'Falla en el sistema de ventilación en Zona Q', '2025-02-03 08:28:38'),
(6, 12, 'Nivel de agua bajo en Zona H', '2025-01-19 08:28:38'),
(7, 66, 'Alerta de contaminación en Zona I', '2025-01-10 08:28:38'),
(8, 148, 'Interrupción eléctrica en Zona J', '2025-01-07 08:28:38'),
(9, 32, 'Exceso de ruido en Zona E', '2025-02-04 08:28:38'),
(10, 103, 'Falla en el sistema de ventilación en Zona Q', '2025-01-22 08:28:38'),
(11, 176, 'Nivel de agua bajo en Zona H', '2025-01-16 08:28:38'),
(12, 131, 'Falla en el sistema de ventilación en Zona Q', '2025-01-15 08:28:38'),
(13, 63, 'Fallo en el sistema de riego en Zona G', '2025-02-02 08:28:38'),
(14, 196, 'Nivel de agua bajo en Zona H', '2025-01-21 08:28:38'),
(15, 77, 'Falla en el sistema de ventilación en Zona Q', '2025-01-07 08:28:38'),
(16, 103, 'Riesgo de derrumbes en Zona K', '2025-01-06 08:28:38'),
(17, 99, 'Alerta de incendios en Zona D', '2025-01-08 08:28:38'),
(18, 113, 'Inundación parcial en Zona T', '2025-01-15 08:28:38'),
(19, 134, 'Riesgo de derrumbes en Zona K', '2025-01-12 08:28:39'),
(20, 85, 'Alerta de contaminación en Zona I', '2025-01-09 08:28:39'),
(21, 38, 'Humedad baja en Zona A', '2025-01-30 08:28:39'),
(22, 173, 'Desprendimiento de rocas en Zona N', '2025-02-03 08:28:39'),
(23, 163, 'Humedad baja en Zona A', '2025-02-02 08:28:39'),
(24, 116, 'Nivel de agua bajo en Zona H', '2025-01-16 08:28:39'),
(25, 84, 'Alerta de incendios en Zona D', '2025-01-18 08:28:39'),
(26, 14, 'Temperatura bajo lo normal en Zona P', '2025-01-20 08:28:39'),
(27, 129, 'Problemas de acceso en Zona S', '2025-01-09 08:28:39'),
(28, 13, 'Temperatura alta en Zona B', '2025-01-18 08:28:39'),
(29, 156, 'Alerta de incendios en Zona D', '2025-01-28 08:28:40'),
(30, 186, 'Temperatura alta en Zona B', '2025-01-29 08:28:40'),
(31, 175, 'Presencia de animales peligrosos en Zona M', '2025-01-27 08:28:40'),
(32, 110, 'Alerta de incendios en Zona D', '2025-02-04 08:28:40'),
(33, 71, 'Fugas de gas detectadas en Zona C', '2025-01-28 08:28:41'),
(34, 68, 'Presencia de animales peligrosos en Zona M', '2025-01-26 08:28:41'),
(35, 196, 'Alerta de incendios en Zona D', '2025-01-18 08:28:41'),
(36, 161, 'Nivel de agua bajo en Zona H', '2025-01-26 08:28:41'),
(37, 122, 'Alerta de contaminación en Zona I', '2025-01-13 08:28:41'),
(38, 124, 'Alerta por infracción de velocidad en Zona L', '2025-01-24 08:28:41'),
(39, 167, 'Interrupción eléctrica en Zona J', '2025-01-13 08:28:41'),
(40, 100, 'Interrupción eléctrica en Zona J', '2025-01-22 08:28:41'),
(41, 198, 'Alerta por rayos en Zona R', '2025-01-23 08:28:41'),
(42, 32, 'Alerta por infracción de velocidad en Zona L', '2025-01-22 08:28:41'),
(43, 175, 'Alerta por infracción de velocidad en Zona L', '2025-01-31 08:28:41'),
(44, 1, 'Fugas de gas detectadas en Zona C', '2025-01-18 08:28:41'),
(45, 39, 'Temperatura alta en Zona B', '2025-01-17 08:28:41'),
(46, 139, 'Desprendimiento de rocas en Zona N', '2025-01-16 08:28:42'),
(47, 87, 'Exceso de ruido en Zona E', '2025-01-17 08:28:42'),
(48, 18, 'Inundación parcial en Zona T', '2025-02-04 08:28:42'),
(49, 199, 'Humedad baja en Zona A', '2025-02-01 08:28:42'),
(50, 83, 'Alerta de incendios en Zona D', '2025-01-25 08:28:42'),
(51, 110, 'Problemas de acceso en Zona S', '2025-02-04 08:28:42'),
(52, 182, 'Alerta por infracción de velocidad en Zona L', '2025-01-11 08:28:42'),
(53, 170, 'Temperatura alta en Zona B', '2025-01-08 08:28:42'),
(54, 34, 'Temperatura bajo lo normal en Zona P', '2025-01-13 08:28:42'),
(55, 72, 'Exceso de ruido en Zona E', '2025-02-03 08:28:42'),
(56, 162, 'Nivel de agua bajo en Zona H', '2025-01-18 08:28:42'),
(57, 99, 'Nivel de agua bajo en Zona H', '2025-01-08 08:28:42'),
(58, 153, 'Accidente de tráfico en Zona O', '2025-02-03 08:28:42'),
(59, 69, 'Problemas de acceso en Zona S', '2025-01-11 08:28:42'),
(60, 92, 'Falla en el sistema de ventilación en Zona Q', '2025-01-22 08:28:42'),
(61, 87, 'Alerta de contaminación en Zona I', '2025-01-22 08:28:42'),
(62, 23, 'Exceso de ruido en Zona E', '2025-01-24 08:28:42'),
(63, 143, 'Alerta por infracción de velocidad en Zona L', '2025-02-02 08:28:42'),
(64, 60, 'Interrupción eléctrica en Zona J', '2025-02-03 08:28:42'),
(65, 135, 'Presencia de animales peligrosos en Zona M', '2025-01-12 08:28:42'),
(66, 133, 'Nivel de agua bajo en Zona H', '2025-01-27 08:28:42'),
(67, 56, 'Alerta por rayos en Zona R', '2025-01-16 08:28:42'),
(68, 144, 'Fallo en el sistema de riego en Zona G', '2025-01-25 08:28:42'),
(69, 109, 'Desprendimiento de rocas en Zona N', '2025-01-20 08:28:42'),
(70, 108, 'Nivel de agua bajo en Zona H', '2025-02-05 08:28:42'),
(71, 180, 'Alerta de incendios en Zona D', '2025-01-28 08:28:43'),
(72, 30, 'Interrupción eléctrica en Zona J', '2025-01-29 08:28:43'),
(73, 129, 'Alerta por rayos en Zona R', '2025-01-18 08:28:43'),
(74, 146, 'Desprendimiento de rocas en Zona N', '2025-01-10 08:28:43'),
(75, 117, 'Problemas de acceso en Zona S', '2025-01-26 08:28:43'),
(76, 46, 'Nivel de agua bajo en Zona H', '2025-01-31 08:28:43'),
(77, 50, 'Presencia de animales peligrosos en Zona M', '2025-01-21 08:28:43'),
(78, 124, 'Temperatura bajo lo normal en Zona P', '2025-01-23 08:28:43'),
(79, 112, 'Nivel de agua bajo en Zona H', '2025-01-07 08:28:43'),
(80, 134, 'Temperatura bajo lo normal en Zona P', '2025-01-16 08:28:43'),
(81, 114, 'Desprendimiento de rocas en Zona N', '2025-01-21 08:28:43'),
(82, 31, 'Interrupción eléctrica en Zona J', '2025-01-19 08:28:43'),
(83, 126, 'Alerta por rayos en Zona R', '2025-01-15 08:28:43'),
(84, 5, 'Fugas de gas detectadas en Zona C', '2025-01-22 08:28:43'),
(85, 28, 'Riesgo de derrumbes en Zona K', '2025-01-08 08:28:43'),
(86, 68, 'Alerta por infracción de velocidad en Zona L', '2025-01-16 08:28:43'),
(87, 68, 'Inundación parcial en Zona T', '2025-01-29 08:28:43'),
(88, 93, 'Temperatura bajo lo normal en Zona P', '2025-02-02 08:28:43'),
(89, 118, 'Problemas de acceso en Zona S', '2025-01-30 08:28:43'),
(90, 166, 'Temperatura alta en Zona B', '2025-01-14 08:28:43'),
(91, 165, 'Alerta de incendios en Zona D', '2025-01-06 08:28:43'),
(92, 19, 'Fugas de gas detectadas en Zona C', '2025-01-09 08:28:43'),
(93, 188, 'Temperatura bajo lo normal en Zona P', '2025-01-24 08:28:43'),
(94, 52, 'Presencia de animales peligrosos en Zona M', '2025-01-13 08:28:43'),
(95, 162, 'Alerta de contaminación en Zona I', '2025-01-25 08:28:44'),
(96, 37, 'Problemas de acceso en Zona S', '2025-01-06 08:28:44'),
(97, 104, 'Exceso de ruido en Zona E', '2025-02-04 08:28:44'),
(98, 175, 'Humedad baja en Zona A', '2025-01-25 08:28:44'),
(99, 33, 'Falla en el sistema de ventilación en Zona Q', '2025-01-26 08:28:44'),
(100, 32, 'Temperatura alta en Zona B', '2025-01-15 08:28:44'),
(101, 37, 'Interrupción eléctrica en Zona J', '2025-01-21 08:28:44'),
(102, 98, 'Temperatura bajo lo normal en Zona P', '2025-01-13 08:28:44');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `configuraciones_riego`
--

CREATE TABLE `configuraciones_riego` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) DEFAULT NULL,
  `umbral_humedad` decimal(5,2) NOT NULL,
  `horario` time NOT NULL,
  `activo` tinyint(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `configuraciones_riego`
--

INSERT INTO `configuraciones_riego` (`id`, `usuario_id`, `umbral_humedad`, `horario`, `activo`) VALUES
(1, 1, 40.00, '06:00:00', 1),
(2, 2, 35.00, '18:00:00', 1),
(3, 54, 32.82, '11:43:00', 0),
(4, 57, 52.69, '08:25:00', 1),
(5, 127, 43.90, '07:14:00', 1),
(6, 109, 49.32, '04:39:00', 0),
(7, 62, 75.13, '12:27:00', 0),
(8, 18, 38.42, '03:52:00', 1),
(9, 40, 60.37, '00:14:00', 1),
(10, 119, 47.13, '23:18:00', 1),
(11, 113, 31.15, '06:03:00', 1),
(12, 171, 62.77, '14:14:00', 1),
(13, 19, 41.30, '10:26:00', 0),
(14, 85, 46.81, '16:35:00', 0),
(15, 94, 62.28, '19:32:00', 1),
(16, 56, 74.52, '07:05:00', 0),
(17, 143, 83.75, '07:26:00', 1),
(18, 138, 42.57, '02:21:00', 1),
(19, 106, 48.31, '00:53:00', 0),
(20, 45, 75.70, '06:42:00', 0),
(21, 74, 66.31, '04:15:00', 1),
(22, 42, 88.22, '16:24:00', 1),
(23, 142, 64.16, '12:08:00', 0),
(24, 18, 77.28, '01:55:00', 0),
(25, 13, 66.16, '01:46:00', 1),
(26, 182, 63.43, '09:12:00', 1),
(27, 41, 58.27, '15:23:00', 0),
(28, 200, 43.75, '16:21:00', 0),
(29, 93, 87.91, '07:39:00', 0),
(30, 27, 83.74, '10:32:00', 0),
(31, 90, 30.05, '05:11:00', 0),
(32, 76, 65.96, '11:25:00', 1),
(33, 78, 30.40, '17:36:00', 1),
(34, 5, 85.99, '21:50:00', 0),
(35, 125, 71.84, '06:05:00', 0),
(36, 129, 89.11, '00:39:00', 1),
(37, 197, 53.55, '17:27:00', 0),
(38, 14, 63.71, '00:44:00', 0),
(39, 63, 33.35, '21:21:00', 1),
(40, 182, 31.97, '13:56:00', 0),
(41, 113, 85.71, '10:04:00', 1),
(42, 62, 58.03, '13:37:00', 0),
(43, 96, 76.46, '11:03:00', 0),
(44, 64, 35.71, '18:36:00', 0),
(45, 27, 59.69, '13:23:00', 0),
(46, 128, 46.78, '12:56:00', 1),
(47, 161, 70.73, '19:30:00', 0),
(48, 55, 46.76, '03:40:00', 0),
(49, 150, 65.98, '05:17:00', 1),
(50, 76, 63.85, '04:18:00', 1),
(51, 45, 31.81, '19:33:00', 1),
(52, 32, 74.60, '17:53:00', 0),
(53, 87, 60.77, '01:20:00', 0),
(54, 20, 67.03, '07:48:00', 1),
(55, 139, 37.10, '16:25:00', 0),
(56, 200, 75.51, '06:28:00', 1),
(57, 157, 47.45, '07:40:00', 1),
(58, 150, 46.44, '22:23:00', 1),
(59, 169, 79.26, '03:16:00', 1),
(60, 172, 69.17, '21:33:00', 1),
(61, 112, 37.13, '06:49:00', 0),
(62, 126, 47.29, '20:35:00', 1),
(63, 7, 57.27, '08:43:00', 0),
(64, 65, 66.80, '09:42:00', 0),
(65, 20, 39.44, '14:56:00', 1),
(66, 63, 79.88, '01:16:00', 0),
(67, 107, 54.63, '12:22:00', 1),
(68, 137, 82.97, '22:51:00', 0),
(69, 134, 68.87, '18:46:00', 0),
(70, 105, 31.95, '22:53:00', 1),
(71, 117, 80.08, '00:19:00', 0),
(72, 114, 70.43, '14:38:00', 1),
(73, 63, 57.67, '22:09:00', 1),
(74, 25, 52.85, '16:05:00', 0),
(75, 31, 64.34, '17:21:00', 0),
(76, 101, 89.93, '16:58:00', 1),
(77, 130, 65.12, '21:55:00', 1),
(78, 8, 62.78, '11:38:00', 1),
(79, 6, 63.85, '08:15:00', 1),
(80, 178, 72.77, '12:14:00', 1),
(81, 134, 43.30, '19:10:00', 0),
(82, 68, 76.31, '12:46:00', 0),
(83, 136, 55.41, '15:25:00', 1),
(84, 44, 30.34, '21:47:00', 1),
(85, 139, 75.92, '11:34:00', 0),
(86, 168, 46.55, '22:37:00', 1),
(87, 42, 57.51, '14:44:00', 0),
(88, 44, 63.02, '05:39:00', 0),
(89, 177, 87.19, '07:57:00', 1),
(90, 13, 53.10, '02:09:00', 1),
(91, 120, 56.86, '20:21:00', 0),
(92, 195, 86.20, '02:16:00', 0),
(93, 70, 75.49, '06:14:00', 1),
(94, 126, 87.02, '14:25:00', 1),
(95, 102, 86.12, '04:58:00', 1),
(96, 104, 65.84, '05:26:00', 1),
(97, 17, 81.86, '03:17:00', 1),
(98, 27, 51.55, '07:06:00', 0),
(99, 111, 70.76, '05:26:00', 0),
(100, 166, 31.51, '07:42:00', 0),
(101, 68, 65.57, '07:36:00', 1),
(102, 120, 68.18, '03:33:00', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `registros_sensores`
--

CREATE TABLE `registros_sensores` (
  `id` int(11) NOT NULL,
  `sensor_id` int(11) DEFAULT NULL,
  `valor` decimal(5,2) NOT NULL,
  `fecha_registro` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `registros_sensores`
--

INSERT INTO `registros_sensores` (`id`, `sensor_id`, `valor`, `fecha_registro`) VALUES
(1, 1, 45.50, '2025-01-29 04:14:35'),
(2, 2, 30.00, '2025-01-29 04:14:35'),
(3, 86, 75.00, '2025-02-04 14:39:34'),
(4, 39, 55.40, '2025-01-31 18:44:34'),
(5, 102, 95.90, '2025-02-04 20:00:34'),
(6, 96, 78.90, '2025-02-03 01:57:34'),
(7, 81, 97.30, '2025-01-31 03:31:34'),
(8, 10, 91.00, '2025-02-04 00:04:34'),
(9, 75, 54.00, '2025-02-02 01:39:34'),
(10, 54, 54.70, '2025-02-04 22:59:35'),
(11, 35, 79.80, '2025-01-30 23:38:35'),
(12, 37, 86.30, '2025-02-02 20:19:35'),
(13, 70, 88.10, '2025-01-30 23:34:35'),
(14, 42, 59.70, '2025-01-31 15:29:35'),
(15, 27, 82.10, '2025-02-03 20:21:35'),
(16, 74, 93.50, '2025-01-31 08:51:35'),
(17, 52, 81.00, '2025-02-01 22:29:35'),
(18, 27, 98.40, '2025-01-30 20:14:36'),
(19, 25, 56.10, '2025-02-02 10:42:36'),
(20, 95, 67.50, '2025-01-31 20:21:36'),
(21, 92, 71.40, '2025-02-01 23:14:36'),
(22, 12, 97.40, '2025-02-01 17:12:36'),
(23, 61, 99.40, '2025-02-01 05:41:36'),
(24, 43, 75.60, '2025-02-05 05:13:36'),
(25, 100, 72.30, '2025-01-30 20:54:36'),
(26, 10, 77.20, '2025-02-04 21:32:36'),
(27, 102, 66.30, '2025-01-30 03:55:36'),
(28, 57, 93.40, '2025-02-02 00:32:36'),
(29, 3, 76.70, '2025-02-03 08:15:36'),
(30, 44, 68.00, '2025-02-02 02:03:36'),
(31, 25, 83.40, '2025-02-05 00:08:36'),
(32, 21, 88.20, '2025-01-30 17:13:36'),
(33, 10, 53.10, '2025-02-04 05:37:36'),
(34, 20, 50.60, '2025-02-03 11:20:36'),
(35, 49, 87.00, '2025-01-31 15:34:36'),
(36, 95, 52.80, '2025-01-30 21:00:37'),
(37, 27, 88.60, '2025-01-31 15:49:37'),
(38, 74, 93.60, '2025-02-03 08:58:37'),
(39, 70, 99.40, '2025-01-30 05:36:37'),
(40, 52, 69.70, '2025-02-03 04:58:37'),
(41, 54, 79.90, '2025-02-02 22:43:37'),
(42, 68, 83.60, '2025-01-30 13:25:37'),
(43, 100, 50.20, '2025-02-02 17:24:37'),
(44, 61, 94.30, '2025-02-01 23:03:37'),
(45, 58, 53.30, '2025-01-29 22:51:37'),
(46, 89, 81.30, '2025-01-29 12:57:37'),
(47, 76, 99.20, '2025-02-02 02:23:37'),
(48, 96, 55.20, '2025-02-02 23:06:37'),
(49, 91, 55.60, '2025-01-30 04:27:37'),
(50, 49, 91.30, '2025-02-03 06:28:37'),
(51, 1, 52.10, '2025-01-31 19:16:37'),
(52, 22, 63.40, '2025-01-29 17:06:37'),
(53, 33, 52.30, '2025-01-30 19:38:37'),
(54, 61, 82.20, '2025-01-31 08:09:37'),
(55, 42, 69.00, '2025-02-04 16:58:37'),
(56, 1, 80.10, '2025-02-01 10:20:38'),
(57, 76, 85.20, '2025-02-03 04:34:38'),
(58, 43, 77.60, '2025-02-03 15:57:38'),
(59, 54, 81.10, '2025-02-01 01:18:38'),
(60, 19, 68.90, '2025-02-01 07:53:38'),
(61, 54, 54.80, '2025-01-31 06:47:38'),
(62, 74, 72.40, '2025-02-02 21:33:38'),
(63, 13, 88.90, '2025-02-03 20:45:39'),
(64, 75, 81.10, '2025-02-05 08:05:39'),
(65, 77, 86.30, '2025-02-01 08:01:39'),
(66, 5, 84.70, '2025-01-31 23:40:39'),
(67, 42, 93.90, '2025-01-30 23:30:39'),
(68, 59, 67.70, '2025-02-03 17:34:39'),
(69, 44, 50.30, '2025-01-29 19:46:39'),
(70, 73, 93.40, '2025-01-29 21:02:39'),
(71, 23, 51.90, '2025-02-01 18:06:39'),
(72, 55, 81.60, '2025-01-30 20:56:39'),
(73, 31, 86.90, '2025-01-29 13:20:39'),
(74, 18, 69.60, '2025-02-03 10:39:39'),
(75, 38, 71.90, '2025-01-31 02:04:39'),
(76, 79, 72.30, '2025-01-30 21:23:39'),
(77, 4, 51.90, '2025-02-02 20:50:39'),
(78, 11, 79.90, '2025-02-05 06:06:39'),
(79, 72, 74.90, '2025-01-30 13:21:39'),
(80, 6, 97.00, '2025-01-30 11:39:39'),
(81, 16, 97.30, '2025-02-02 12:57:39'),
(82, 93, 51.90, '2025-02-04 11:17:39'),
(83, 50, 59.20, '2025-01-30 00:27:39'),
(84, 86, 78.00, '2025-02-04 07:09:39'),
(85, 14, 80.00, '2025-02-05 01:20:39'),
(86, 60, 92.40, '2025-01-30 18:37:40'),
(87, 32, 64.10, '2025-02-02 02:00:40'),
(88, 95, 78.90, '2025-02-04 21:29:40'),
(89, 43, 79.50, '2025-02-01 16:28:40'),
(90, 64, 77.40, '2025-01-30 23:48:40'),
(91, 49, 84.90, '2025-02-05 01:16:40'),
(92, 15, 70.00, '2025-02-05 03:15:40'),
(93, 13, 76.00, '2025-01-31 04:52:40'),
(94, 20, 70.00, '2025-02-01 17:40:40'),
(95, 64, 98.40, '2025-02-04 09:37:40'),
(96, 76, 55.50, '2025-01-30 18:48:40'),
(97, 21, 71.70, '2025-01-29 16:05:40'),
(98, 11, 58.90, '2025-01-30 08:20:40'),
(99, 44, 61.60, '2025-01-29 23:47:40'),
(100, 58, 77.30, '2025-01-30 02:14:40'),
(101, 101, 87.40, '2025-02-04 22:00:40'),
(102, 57, 65.30, '2025-02-04 09:49:41');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `riegos`
--

CREATE TABLE `riegos` (
  `id` int(11) NOT NULL,
  `valvula_id` int(11) DEFAULT NULL,
  `cantidad_agua` decimal(5,2) NOT NULL,
  `duracion` int(11) NOT NULL,
  `fecha_riego` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `riegos`
--

INSERT INTO `riegos` (`id`, `valvula_id`, `cantidad_agua`, `duracion`, `fecha_riego`) VALUES
(1, 1, 10.50, 60, '2025-01-29 04:15:09'),
(2, 2, 15.00, 90, '2025-01-29 04:15:09'),
(3, 98, 1.40, 64, '2024-05-13 08:43:12'),
(4, 12, 17.90, 112, '2024-10-14 08:43:12'),
(5, 36, 9.80, 36, '2024-08-27 08:43:12'),
(6, 35, 9.00, 113, '2024-09-26 08:43:12'),
(7, 13, 6.20, 66, '2024-11-11 08:43:12'),
(8, 11, 19.10, 87, '2024-10-19 08:43:12'),
(9, 18, 15.40, 91, '2025-01-06 08:43:12'),
(10, 18, 9.10, 73, '2024-05-16 08:43:12'),
(11, 60, 18.80, 31, '2025-01-29 08:43:13'),
(12, 59, 3.60, 80, '2024-12-26 08:43:13'),
(13, 40, 14.60, 38, '2024-05-23 08:43:13'),
(14, 6, 18.00, 47, '2024-03-01 08:43:13'),
(15, 78, 17.70, 70, '2024-10-18 08:43:13'),
(16, 90, 19.00, 73, '2024-03-13 08:43:13'),
(17, 11, 15.00, 100, '2024-07-10 08:43:13'),
(18, 66, 12.90, 80, '2024-09-23 08:43:13'),
(19, 52, 14.20, 85, '2024-08-13 08:43:13'),
(20, 72, 13.70, 115, '2024-10-19 08:43:13'),
(21, 77, 17.00, 62, '2024-04-23 08:43:13'),
(22, 70, 6.10, 88, '2024-11-24 08:43:13'),
(23, 38, 14.20, 93, '2024-05-07 08:43:13'),
(24, 25, 5.00, 57, '2024-03-03 08:43:13'),
(25, 12, 4.30, 45, '2025-02-04 08:43:13'),
(26, 1, 4.40, 111, '2024-06-26 08:43:13'),
(27, 42, 1.30, 67, '2025-01-23 08:43:13'),
(28, 50, 6.90, 69, '2024-10-14 08:43:13'),
(29, 19, 2.00, 55, '2024-09-02 08:43:13'),
(30, 100, 5.80, 58, '2024-09-16 08:43:13'),
(31, 78, 11.80, 37, '2024-12-20 08:43:13'),
(32, 11, 1.10, 82, '2024-03-27 08:43:13'),
(33, 7, 7.60, 37, '2024-12-10 08:43:14'),
(34, 99, 5.90, 56, '2024-02-23 08:43:14'),
(35, 9, 11.20, 100, '2024-11-21 08:43:14'),
(36, 34, 11.00, 45, '2024-12-17 08:43:14'),
(37, 56, 4.90, 108, '2024-08-01 08:43:14'),
(38, 63, 9.40, 59, '2024-05-19 08:43:14'),
(39, 4, 15.70, 72, '2025-01-19 08:43:14'),
(40, 40, 2.40, 118, '2024-10-10 08:43:14'),
(41, 99, 4.60, 57, '2025-02-01 08:43:14'),
(42, 4, 10.70, 106, '2024-07-06 08:43:14'),
(43, 62, 9.10, 79, '2024-11-21 08:43:14'),
(44, 65, 13.10, 45, '2024-05-15 08:43:14'),
(45, 62, 18.80, 54, '2024-09-30 08:43:14'),
(46, 40, 16.20, 100, '2024-08-20 08:43:14'),
(47, 4, 1.20, 48, '2024-11-24 08:43:14'),
(48, 62, 12.10, 65, '2024-02-21 08:43:14'),
(49, 1, 6.20, 104, '2024-12-12 08:43:14'),
(50, 19, 5.70, 113, '2024-11-24 08:43:15'),
(51, 59, 6.90, 57, '2024-07-23 08:43:15'),
(52, 42, 9.60, 36, '2024-03-12 08:43:15'),
(53, 10, 1.10, 94, '2024-04-06 08:43:15'),
(54, 78, 17.90, 62, '2024-03-03 08:43:15'),
(55, 32, 19.40, 96, '2024-03-29 08:43:15'),
(56, 62, 3.20, 42, '2024-07-31 08:43:15'),
(57, 69, 8.30, 69, '2025-01-14 08:43:15'),
(58, 84, 10.50, 91, '2024-10-22 08:43:15'),
(59, 14, 9.00, 86, '2024-10-04 08:43:15'),
(60, 91, 8.90, 36, '2024-08-07 08:43:15'),
(61, 22, 1.60, 85, '2025-01-13 08:43:15'),
(62, 38, 8.00, 80, '2024-10-08 08:43:15'),
(63, 28, 12.90, 102, '2024-04-03 08:43:15'),
(64, 57, 12.50, 40, '2024-05-19 08:43:15'),
(65, 100, 7.60, 104, '2024-07-23 08:43:15'),
(66, 6, 5.10, 116, '2024-05-30 08:43:15'),
(67, 74, 11.00, 73, '2024-12-28 08:43:15'),
(68, 88, 3.20, 91, '2024-10-06 08:43:15'),
(69, 13, 16.20, 112, '2024-10-06 08:43:15'),
(70, 36, 13.80, 108, '2024-09-22 08:43:15'),
(71, 18, 13.10, 36, '2024-09-03 08:43:16'),
(72, 99, 17.90, 31, '2024-09-11 08:43:16'),
(73, 33, 12.40, 44, '2024-11-27 08:43:16'),
(74, 65, 17.30, 30, '2024-12-21 08:43:16'),
(75, 75, 6.20, 84, '2024-05-13 08:43:16'),
(76, 98, 15.90, 84, '2025-01-04 08:43:16'),
(77, 59, 12.40, 68, '2024-12-15 08:43:16'),
(78, 71, 10.00, 98, '2024-06-09 08:43:16'),
(79, 58, 14.70, 110, '2024-10-27 08:43:16'),
(80, 32, 16.90, 33, '2024-08-15 08:43:16'),
(81, 9, 15.30, 108, '2024-11-16 08:43:16'),
(82, 6, 6.80, 72, '2024-05-11 08:43:17'),
(83, 43, 8.90, 44, '2024-03-29 08:43:17'),
(84, 66, 10.70, 60, '2024-02-16 08:43:17'),
(85, 38, 13.00, 115, '2024-04-10 08:43:17'),
(86, 28, 8.10, 99, '2024-04-05 08:43:17'),
(87, 72, 1.30, 56, '2025-01-03 08:43:17'),
(88, 31, 13.50, 71, '2024-11-04 08:43:17'),
(89, 14, 6.00, 90, '2024-04-06 08:43:17'),
(90, 53, 7.90, 102, '2024-12-03 08:43:17'),
(91, 59, 14.70, 49, '2024-05-03 08:43:17'),
(92, 32, 2.80, 115, '2024-11-30 08:43:17'),
(93, 19, 10.90, 112, '2024-11-08 08:43:17'),
(94, 42, 18.40, 48, '2024-10-29 08:43:18'),
(95, 17, 16.80, 57, '2024-11-25 08:43:18'),
(96, 16, 17.20, 52, '2024-03-12 08:43:18'),
(97, 27, 4.10, 95, '2024-07-05 08:43:18'),
(98, 30, 13.50, 65, '2024-12-07 08:43:18'),
(99, 93, 6.10, 44, '2024-11-17 08:43:18'),
(100, 84, 10.40, 75, '2024-11-14 08:43:18'),
(101, 23, 6.80, 104, '2024-12-24 08:43:18'),
(102, 7, 4.00, 61, '2024-02-15 08:43:18');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `sensores`
--

CREATE TABLE `sensores` (
  `id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `tipo` enum('Humedad','Temperatura') NOT NULL,
  `ubicacion` varchar(100) DEFAULT NULL,
  `fecha_instalacion` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `sensores`
--

INSERT INTO `sensores` (`id`, `nombre`, `tipo`, `ubicacion`, `fecha_instalacion`) VALUES
(1, 'Sensor1', 'Humedad', 'Zona A', '2025-01-29 04:14:11'),
(2, 'Sensor2', 'Temperatura', 'Zona B', '2025-01-29 04:14:11'),
(3, 'Sensor 1', 'Temperatura', 'Zona 10', '2024-06-04 08:35:11'),
(4, 'Sensor 2', 'Temperatura', NULL, '2024-07-24 08:35:11'),
(5, 'Sensor 3', 'Temperatura', 'Zona 8', '2024-11-08 08:35:11'),
(6, 'Sensor 4', 'Temperatura', 'Zona 5', '2024-12-03 08:35:12'),
(7, 'Sensor 5', 'Humedad', 'Zona 6', '2024-12-05 08:35:12'),
(8, 'Sensor 6', 'Temperatura', NULL, '2024-10-23 08:35:12'),
(9, 'Sensor 7', 'Humedad', NULL, '2024-12-14 08:35:12'),
(10, 'Sensor 8', 'Humedad', NULL, '2024-03-27 08:35:12'),
(11, 'Sensor 9', 'Temperatura', NULL, '2024-03-30 08:35:12'),
(12, 'Sensor 10', 'Humedad', 'Zona 1', '2024-07-27 08:35:12'),
(13, 'Sensor 11', 'Humedad', 'Zona 8', '2025-01-25 08:35:12'),
(14, 'Sensor 12', 'Temperatura', NULL, '2024-07-13 08:35:12'),
(15, 'Sensor 13', 'Humedad', NULL, '2024-07-04 08:35:12'),
(16, 'Sensor 14', 'Temperatura', NULL, '2024-06-29 08:35:12'),
(17, 'Sensor 15', 'Humedad', NULL, '2024-09-13 08:35:12'),
(18, 'Sensor 16', 'Temperatura', 'Zona 4', '2024-11-12 08:35:12'),
(19, 'Sensor 17', 'Temperatura', 'Zona 4', '2024-12-26 08:35:12'),
(20, 'Sensor 18', 'Temperatura', NULL, '2024-09-01 08:35:13'),
(21, 'Sensor 19', 'Humedad', 'Zona 10', '2024-06-23 08:35:13'),
(22, 'Sensor 20', 'Humedad', 'Zona 4', '2024-12-03 08:35:13'),
(23, 'Sensor 21', 'Humedad', NULL, '2024-04-30 08:35:13'),
(24, 'Sensor 22', 'Humedad', NULL, '2024-03-19 08:35:13'),
(25, 'Sensor 23', 'Temperatura', NULL, '2024-08-16 08:35:13'),
(26, 'Sensor 24', 'Humedad', 'Zona 1', '2024-09-29 08:35:14'),
(27, 'Sensor 25', 'Temperatura', 'Zona 4', '2024-08-12 08:35:14'),
(28, 'Sensor 26', 'Humedad', NULL, '2025-01-04 08:35:14'),
(29, 'Sensor 27', 'Humedad', 'Zona 2', '2024-03-13 08:35:14'),
(30, 'Sensor 28', 'Temperatura', NULL, '2024-09-01 08:35:14'),
(31, 'Sensor 29', 'Temperatura', NULL, '2024-03-08 08:35:14'),
(32, 'Sensor 30', 'Humedad', 'Zona 1', '2024-09-28 08:35:14'),
(33, 'Sensor 31', 'Humedad', 'Zona 8', '2024-12-02 08:35:14'),
(34, 'Sensor 32', 'Temperatura', 'Zona 1', '2024-11-21 08:35:15'),
(35, 'Sensor 33', 'Humedad', 'Zona 1', '2024-11-29 08:35:15'),
(36, 'Sensor 34', 'Temperatura', NULL, '2024-03-02 08:35:15'),
(37, 'Sensor 35', 'Temperatura', NULL, '2024-04-01 08:35:15'),
(38, 'Sensor 36', 'Humedad', NULL, '2025-01-04 08:35:15'),
(39, 'Sensor 37', 'Temperatura', NULL, '2024-05-27 08:35:15'),
(40, 'Sensor 38', 'Humedad', 'Zona 9', '2024-11-28 08:35:15'),
(41, 'Sensor 39', 'Temperatura', NULL, '2024-03-30 08:35:15'),
(42, 'Sensor 40', 'Temperatura', 'Zona 6', '2024-04-13 08:35:15'),
(43, 'Sensor 41', 'Humedad', 'Zona 6', '2025-01-01 08:35:15'),
(44, 'Sensor 42', 'Temperatura', 'Zona 5', '2024-10-24 08:35:15'),
(45, 'Sensor 43', 'Temperatura', 'Zona 6', '2024-11-01 08:35:15'),
(46, 'Sensor 44', 'Humedad', 'Zona 4', '2024-05-11 08:35:15'),
(47, 'Sensor 45', 'Humedad', 'Zona 4', '2024-07-11 08:35:15'),
(48, 'Sensor 46', 'Temperatura', NULL, '2024-03-25 08:35:15'),
(49, 'Sensor 47', 'Temperatura', 'Zona 2', '2024-07-15 08:35:15'),
(50, 'Sensor 48', 'Temperatura', 'Zona 3', '2024-05-19 08:35:15'),
(51, 'Sensor 49', 'Humedad', 'Zona 2', '2024-08-16 08:35:15'),
(52, 'Sensor 50', 'Humedad', 'Zona 3', '2024-06-11 08:35:15'),
(53, 'Sensor 51', 'Humedad', 'Zona 5', '2024-06-12 08:35:15'),
(54, 'Sensor 52', 'Temperatura', 'Zona 1', '2024-03-21 08:35:15'),
(55, 'Sensor 53', 'Temperatura', NULL, '2024-03-12 08:35:15'),
(56, 'Sensor 54', 'Temperatura', NULL, '2024-12-03 08:35:16'),
(57, 'Sensor 55', 'Temperatura', NULL, '2024-06-03 08:35:16'),
(58, 'Sensor 56', 'Humedad', 'Zona 1', '2024-04-03 08:35:16'),
(59, 'Sensor 57', 'Temperatura', 'Zona 3', '2024-09-27 08:35:16'),
(60, 'Sensor 58', 'Humedad', 'Zona 1', '2024-08-23 08:35:16'),
(61, 'Sensor 59', 'Humedad', 'Zona 7', '2025-01-29 08:35:16'),
(62, 'Sensor 60', 'Temperatura', NULL, '2024-10-09 08:35:16'),
(63, 'Sensor 61', 'Humedad', 'Zona 7', '2024-09-08 08:35:16'),
(64, 'Sensor 62', 'Temperatura', 'Zona 4', '2024-11-30 08:35:16'),
(65, 'Sensor 63', 'Humedad', NULL, '2024-09-26 08:35:16'),
(66, 'Sensor 64', 'Temperatura', NULL, '2024-08-22 08:35:16'),
(67, 'Sensor 65', 'Humedad', 'Zona 10', '2024-07-22 08:35:16'),
(68, 'Sensor 66', 'Temperatura', NULL, '2024-09-29 08:35:16'),
(69, 'Sensor 67', 'Temperatura', NULL, '2024-04-04 08:35:17'),
(70, 'Sensor 68', 'Temperatura', 'Zona 6', '2024-11-27 08:35:17'),
(71, 'Sensor 69', 'Humedad', NULL, '2024-12-01 08:35:17'),
(72, 'Sensor 70', 'Humedad', NULL, '2024-09-05 08:35:17'),
(73, 'Sensor 71', 'Humedad', NULL, '2024-08-20 08:35:17'),
(74, 'Sensor 72', 'Temperatura', 'Zona 5', '2024-08-07 08:35:17'),
(75, 'Sensor 73', 'Humedad', 'Zona 3', '2024-10-29 08:35:17'),
(76, 'Sensor 74', 'Humedad', NULL, '2024-02-22 08:35:17'),
(77, 'Sensor 75', 'Humedad', NULL, '2024-09-12 08:35:17'),
(78, 'Sensor 76', 'Temperatura', 'Zona 9', '2024-11-27 08:35:17'),
(79, 'Sensor 77', 'Temperatura', NULL, '2024-03-01 08:35:17'),
(80, 'Sensor 78', 'Humedad', 'Zona 1', '2025-01-11 08:35:17'),
(81, 'Sensor 79', 'Temperatura', NULL, '2024-02-28 08:35:17'),
(82, 'Sensor 80', 'Temperatura', NULL, '2024-08-10 08:35:17'),
(83, 'Sensor 81', 'Temperatura', 'Zona 10', '2024-12-09 08:35:17'),
(84, 'Sensor 82', 'Temperatura', 'Zona 3', '2024-05-28 08:35:17'),
(85, 'Sensor 83', 'Temperatura', 'Zona 9', '2024-11-14 08:35:17'),
(86, 'Sensor 84', 'Temperatura', NULL, '2024-04-19 08:35:18'),
(87, 'Sensor 85', 'Humedad', 'Zona 9', '2024-04-24 08:35:18'),
(88, 'Sensor 86', 'Temperatura', NULL, '2024-02-20 08:35:18'),
(89, 'Sensor 87', 'Temperatura', 'Zona 7', '2024-03-16 08:35:18'),
(90, 'Sensor 88', 'Humedad', 'Zona 5', '2024-08-25 08:35:18'),
(91, 'Sensor 89', 'Humedad', NULL, '2024-11-12 08:35:18'),
(92, 'Sensor 90', 'Temperatura', NULL, '2024-05-29 08:35:18'),
(93, 'Sensor 91', 'Humedad', NULL, '2024-10-08 08:35:18'),
(94, 'Sensor 92', 'Humedad', NULL, '2024-05-27 08:35:18'),
(95, 'Sensor 93', 'Temperatura', NULL, '2025-01-07 08:35:18'),
(96, 'Sensor 94', 'Temperatura', 'Zona 10', '2024-09-12 08:35:18'),
(97, 'Sensor 95', 'Temperatura', NULL, '2024-09-07 08:35:18'),
(98, 'Sensor 96', 'Humedad', NULL, '2024-10-06 08:35:18'),
(99, 'Sensor 97', 'Humedad', 'Zona 2', '2024-04-04 08:35:18'),
(100, 'Sensor 98', 'Humedad', NULL, '2024-06-03 08:35:18'),
(101, 'Sensor 99', 'Humedad', 'Zona 1', '2024-10-04 08:35:19'),
(102, 'Sensor 100', 'Temperatura', 'Zona 9', '2024-11-27 08:35:19');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuarios`
--

CREATE TABLE `usuarios` (
  `id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `correo` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `rol` enum('Administrador','Usuario','Sistema') NOT NULL,
  `foto` varchar(255) NOT NULL,
  `fecha_nacimiento` date NOT NULL,
  `sexo` enum('Masculino','Femenino','Otro') NOT NULL,
  `fecha_registro` timestamp NOT NULL DEFAULT current_timestamp(),
  `failed_attempts` int(11) DEFAULT 0,
  `lock_time` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `usuarios`
--

INSERT INTO `usuarios` (`id`, `nombre`, `correo`, `password`, `rol`, `foto`, `fecha_nacimiento`, `sexo`, `fecha_registro`, `failed_attempts`, `lock_time`) VALUES
(1, 'Admin', 'admin@sistemariego.com', 'admin123', 'Administrador', '', '0000-00-00', '', '2025-01-29 04:13:48', 0, NULL),
(2, 'Usuario1', 'usuario1@sistemariego.com', 'usuario123', 'Usuario', '', '0000-00-00', '', '2025-01-29 04:13:48', 0, NULL),
(3, 'Usuario0', 'usuario0@correo.com', '$2y$12$IqMrYRbVN0K473Ab7TzHTeyhO9qGHaGSFs42MHuJ31AUfFQSiSu2u', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:20:42', 0, NULL),
(4, 'Usuario1', 'usuario1@correo.com', '$2y$12$MZoYmcemeaeSoKWcjva/LestEu9zgR81DAUTLnJNobF0jmvGuavC2', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:20:44', 0, NULL),
(5, 'Usuario2', 'usuario2@correo.com', '$2y$12$ZQjQ6hishrHVMLfbLuoi.eddWEkLgMAmIYs5WCYzUrP7ha6SgMufm', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:20:45', 0, NULL),
(6, 'Usuario3', 'usuario3@correo.com', '$2y$12$AKj5WoeR/8YCgLy0/Su0SunHSzkDS09J56dtRQ8dCrYasSsSnDSuu', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:20:47', 0, NULL),
(7, 'Usuario4', 'usuario4@correo.com', '$2y$12$kBJXKkEt9vAbkRB8Fn6/ROjZg4K1waLN4sZe87RStBeVTp5.J1MtK', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:20:47', 0, NULL),
(8, 'Usuario5', 'usuario5@correo.com', '$2y$12$TaVs4ClgI8A4JFRu7QeKTuewuzHnvX.h/n9.C8nt3NqE4xYZPJP8G', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:20:49', 0, NULL),
(9, 'Usuario6', 'usuario6@correo.com', '$2y$12$mcgFgomsXoNQne/X80EhZOTaBdrhFnh3G9haXXYjpOnNx3dalp1um', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:20:51', 0, NULL),
(10, 'Usuario7', 'usuario7@correo.com', '$2y$12$Ahk/UVjHCiBkWbf4FO1rHeWx4Tnym7Co/JSiENSXSgAEQIhX6FeVG', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:20:53', 0, NULL),
(11, 'Usuario8', 'usuario8@correo.com', '$2y$12$jhzsoX5r6owP8MvHrT8FG.nwvJHd7uAStOHBZTzBMHBqHD68WDYfm', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:20:55', 0, NULL),
(12, 'Usuario9', 'usuario9@correo.com', '$2y$12$z/KK851fZiMlXggYYXNuNue.tUUCT4r3n7Rdh7Qqc1e4X1RQaWq7a', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:20:55', 0, NULL),
(13, 'Usuario10', 'usuario10@correo.com', '$2y$12$1yqifwQZgF.vxxpTNtzHleqPO/zW3EFlVL7BibQMLTKL1qmtKA3zi', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:20:57', 0, NULL),
(14, 'Usuario11', 'usuario11@correo.com', '$2y$12$vmpIeT8PNN.1o0oV5mU2H.d0d9iVM11k9jEjk4xwCIYg2c21ut9ge', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:20:58', 0, NULL),
(15, 'Usuario12', 'usuario12@correo.com', '$2y$12$eEpK6wjW5YCL/zSXII0Rg.1oUHyAJCb/a5WwUeSn/YHXdTHgNCtJ2', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:20:59', 0, NULL),
(16, 'Usuario13', 'usuario13@correo.com', '$2y$12$IxnaYNnBkWIBHYwtHPuWz.SImS4rWW9WUFzsjzQrSEhr42bX6inxC', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:01', 0, NULL),
(17, 'Usuario14', 'usuario14@correo.com', '$2y$12$2MUW.vAgw8qcLOQbenTwKuiCVfGPnCUop9FT4pwvYmQXSioMOeP7u', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:02', 0, NULL),
(18, 'Usuario15', 'usuario15@correo.com', '$2y$12$sgC/MhEfRtEJCIocjKtibO7pyGCTn6kHeUn3btStLIXNVUASRq3V2', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:03', 0, NULL),
(19, 'Usuario16', 'usuario16@correo.com', '$2y$12$jSSdZuTya0czaEG8O0Kqhuj/l1cElD4AdyWTKVl0d8V4pQOepTnjC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:04', 0, NULL),
(20, 'Usuario17', 'usuario17@correo.com', '$2y$12$tBG13h7D6nKy2EgOiTM2le5lVDeY5TSb7pq8H9gXMwwcQAGIN4WMm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:05', 0, NULL),
(21, 'Usuario18', 'usuario18@correo.com', '$2y$12$00DaT.RW7N0x1FEO45WuNODEyUOPcMBZdncyH6.aZynKgtTDPdQ0S', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:06', 0, NULL),
(22, 'Usuario19', 'usuario19@correo.com', '$2y$12$LYWZMpbhAmi8pCdADN5NOOqoLLfjurv8l8vfV0HXwoma9pWQF6L8i', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:07', 0, NULL),
(23, 'Usuario20', 'usuario20@correo.com', '$2y$12$IQ1lNjYkEoqfq84zqVoTyO8NPm23CQXWATcl6wr03noaFYLpWoVda', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:08', 0, NULL),
(24, 'Usuario21', 'usuario21@correo.com', '$2y$12$uuvkkJ.RWOxMuln14qf5dewtxQyAXp5uOcfZN8ACE5FVBq9ttLpuG', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:08', 0, NULL),
(25, 'Usuario22', 'usuario22@correo.com', '$2y$12$QqMPr0/2e1S7w5XGpclPnudK0l7XlW7J5sguULSWTUSWiYNRJuOra', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:09', 0, NULL),
(26, 'Usuario23', 'usuario23@correo.com', '$2y$12$B2zKdwJg9QgshTDlhXvLb.5/szN6hXBgNtceUWv06TyrnhF4LMm3K', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:09', 0, NULL),
(27, 'Usuario24', 'usuario24@correo.com', '$2y$12$xzZy6MdD2Mp2/pgcAP3eGOiQc2w.nLjAtah5inls421Y9PJH2mWH.', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:10', 0, NULL),
(28, 'Usuario25', 'usuario25@correo.com', '$2y$12$sDPiefkhzzkobGI0E/aRn./8bYOtuXz7uuRX03YO2FLjkcSELQYgO', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:10', 0, NULL),
(29, 'Usuario26', 'usuario26@correo.com', '$2y$12$fC1Yu82y0ntpyJJTkpnJrO/IXwAT6iHErBjrJOKL.9Mmwlj8Cy67a', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:11', 0, NULL),
(30, 'Usuario27', 'usuario27@correo.com', '$2y$12$znLH3NhrRS.VLollsGzXX.PZcVDOwDjG3vwsZqTE0kvBCd0rg8bdG', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:12', 0, NULL),
(31, 'Usuario28', 'usuario28@correo.com', '$2y$12$O8/5t4C27qLfoDp7bwQpQuzjD2QRZxvugMWkMkkT4iX4h0Opvce4K', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:12', 0, NULL),
(32, 'Usuario29', 'usuario29@correo.com', '$2y$12$gT1sz5ZGI.bWmv7Hi4WEM.P7dvTRpfUi04bh4PQbOwF5lGxpLPJ5S', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:13', 0, NULL),
(33, 'Usuario30', 'usuario30@correo.com', '$2y$12$cOR.gl0y95EwkMhvx0S.E.9OhOJU/JSepSvR47gKKEb9a5o/DtRIC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:13', 0, NULL),
(34, 'Usuario31', 'usuario31@correo.com', '$2y$12$UkMhNOUJicyTaIkEEXdD6u1EfrGaasGt54vKPDjQsVc8UVtNbIXW.', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:14', 0, NULL),
(35, 'Usuario32', 'usuario32@correo.com', '$2y$12$pMvkTTTOeb65ttSRkoLiGeDQCemezeDrt8DFaadmoLWvILzaPW8uu', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:15', 0, NULL),
(36, 'Usuario33', 'usuario33@correo.com', '$2y$12$D/ntmv69TwUK8yYSxYLyjOL4d9d.FDzj8Oe/VNGcOjzJ0HGDWD0e6', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:15', 0, NULL),
(37, 'Usuario34', 'usuario34@correo.com', '$2y$12$zTDtZFy6r7wjIz1pI4O0NOUsboRzrolE3.VCjmcDVyCm5lujds3KG', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:16', 0, NULL),
(38, 'Usuario35', 'usuario35@correo.com', '$2y$12$3HZZyCOtjCHAJ60X0G7Rh.e33P0Fp1ACs2ECJ8SbZwliVTvXG5l8C', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:16', 0, NULL),
(39, 'Usuario36', 'usuario36@correo.com', '$2y$12$hGOSGyAzkpkLge95yRM3SedJNLvvh6PRNmkNRVGeeDe6SjbkP1nD2', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:17', 0, NULL),
(40, 'Usuario37', 'usuario37@correo.com', '$2y$12$cTQxm.D.XEKjxBpo0x85D.D8YfiKIe/kyMZba0TpLJ.5FXC53qtBm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:17', 0, NULL),
(41, 'Usuario38', 'usuario38@correo.com', '$2y$12$ODYKrwjns4GJkflYHusM/.xQbMesoDkfFe8I6aSFJMoR0GuAmIwNC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:18', 0, NULL),
(42, 'Usuario39', 'usuario39@correo.com', '$2y$12$quVABHVZkTpXnU6.JZqmiOMRRw0OgfUZln75xoO2AVO2ZOHuWdkgO', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:18', 0, NULL),
(43, 'Usuario40', 'usuario40@correo.com', '$2y$12$gFYocV/o8kG1ToSMOls8GOwsQzW73Ldj67B7ODP6lPe/stkHuJKVy', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:19', 0, NULL),
(44, 'Usuario41', 'usuario41@correo.com', '$2y$12$aRNf6KPM/cvWVP7ks8RifuBgDf/eskdIPYsWkhk9exfOEvyPof0ci', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:19', 0, NULL),
(45, 'Usuario42', 'usuario42@correo.com', '$2y$12$FLd2og1qKjKZaCFm.sqiuOC2AzduRgOH7UQBQ10W3yTz3GcFpD4Xa', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:20', 0, NULL),
(46, 'Usuario43', 'usuario43@correo.com', '$2y$12$jx0eqQpFfjR7onPgkQ8ZjuddJoKMrIs1MsLXcTxQlHXRwZ6y5erH2', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:20', 0, NULL),
(47, 'Usuario44', 'usuario44@correo.com', '$2y$12$SR7Bmij..beII071ZLV4f.hstjFhvKukaTPpGATqv7drue4VFwAai', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:21', 0, NULL),
(48, 'Usuario45', 'usuario45@correo.com', '$2y$12$tAmZvoEaa5zBl28AaA3T1.JCV.Y73ec/RuhT4a8ierssG96Nsr60a', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:22', 0, NULL),
(49, 'Usuario46', 'usuario46@correo.com', '$2y$12$7lkLJI54dKftFOMUDzlD9OdTGxqrqKfm0fbIWEpNBTIiwSjv8YGgS', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:22', 0, NULL),
(50, 'Usuario47', 'usuario47@correo.com', '$2y$12$JD6bHLAxFCT9LsbCr56.beTxKBVua6OTVsQhNrLSY2aLUJMsTvT0.', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:23', 0, NULL),
(51, 'Usuario48', 'usuario48@correo.com', '$2y$12$YJYM0tEHHB/NMLYdVE435.zrCweXUDld0wkxLNvK90VFQStbMgiCy', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:23', 0, NULL),
(52, 'Usuario49', 'usuario49@correo.com', '$2y$12$XOdcbiv6MDduvf6eLN0cWekGgUj0AJM.KUPGPwa/mwteeVPgVB6Hm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:24', 0, NULL),
(53, 'Usuario50', 'usuario50@correo.com', '$2y$12$SxnaeU69ZPSntGOGa/a/2OdUaTp86/Jx5KMwMmQKbzic3.wTVab4i', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:24', 0, NULL),
(54, 'Usuario51', 'usuario51@correo.com', '$2y$12$THsbiGCL1lWoKpYM5gDypOvDphASd5yq06kOe73y9P7R7YzJVgmuu', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:25', 0, NULL),
(55, 'Usuario52', 'usuario52@correo.com', '$2y$12$7JLgfWZymDMNFIfwp6ZFx.c3z/TfDV8OX8ibDOUNpcUIg.Cpz7tKW', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:25', 0, NULL),
(56, 'Usuario53', 'usuario53@correo.com', '$2y$12$0IUB0MNjkQKDAvZUz/IkIeJpZ2B/XT0LZVOI1houVsK.RonrTFnRu', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:26', 0, NULL),
(57, 'Usuario54', 'usuario54@correo.com', '$2y$12$ULNNCw5OhJNQHGOMf9oN/eiOc19sYjWk08OOhqtaYDrvd3gEVHdGO', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:26', 0, NULL),
(58, 'Usuario55', 'usuario55@correo.com', '$2y$12$ot9remb01Y2CeYd2KSv/p.nf68HK0CXDX6vuJkhcCOA4KtLvJxzSS', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:27', 0, NULL),
(59, 'Usuario56', 'usuario56@correo.com', '$2y$12$byBH3fXvRnokNw3XXTOuveF4ufBQfLXKsyO3rXMe.I4zAweBBY.ny', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:27', 0, NULL),
(60, 'Usuario57', 'usuario57@correo.com', '$2y$12$uhGpcyDLY9srvduBKQIAY.K.MEokYi.JIhxu8LzRSNuXV8tG6mQiu', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:28', 0, NULL),
(61, 'Usuario58', 'usuario58@correo.com', '$2y$12$7HNL6NLLJrkov3PnwkYj8uNJZGjyEC7Aailjr3vUpbjaxMLzZ1HhK', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:28', 0, NULL),
(62, 'Usuario59', 'usuario59@correo.com', '$2y$12$zpz7Nv1LhCWDC5mMwWs7ZevUvOzXU/SLWpeosF0Ceezf0T2giDa4C', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:29', 0, NULL),
(63, 'Usuario60', 'usuario60@correo.com', '$2y$12$S2DUgdQ75fPE2SPYee/kqO3yjTQnye34FOaJD8eHowW0/KAIi5s0W', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:30', 0, NULL),
(64, 'Usuario61', 'usuario61@correo.com', '$2y$12$aYE50ndiwVzTRsYCdkLbDu0aUeT7TVkgxQLSLak486DYowksf01j.', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:30', 0, NULL),
(65, 'Usuario62', 'usuario62@correo.com', '$2y$12$C/gSfb0pTMJ6oJFua.8R5.XmgcC/fNYcvuQEoSg5InPZZY1znaEMq', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:31', 0, NULL),
(66, 'Usuario63', 'usuario63@correo.com', '$2y$12$OhHsre/09HzKcx1Ba6ycQuSn85XBWZGAQSivL/PijjulWZGZCidbm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:32', 0, NULL),
(67, 'Usuario64', 'usuario64@correo.com', '$2y$12$e7e8eaZfcmT23GNx0PtBR.LVesattd3GmLmt5mrftRHCNcfwbFN.C', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:32', 0, NULL),
(68, 'Usuario65', 'usuario65@correo.com', '$2y$12$UXekIVHzV6aqd0kegutbJ.pdceFzI5Tj19wAVtRvx0jd2qTJgO3Jy', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:33', 0, NULL),
(69, 'Usuario66', 'usuario66@correo.com', '$2y$12$FxTn57QzSiuqEpYLMKnKL.Lq09fBiLF/pvsCByFPEbfbtN1n4n.m6', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:33', 0, NULL),
(70, 'Usuario67', 'usuario67@correo.com', '$2y$12$ZcmBzhBKlS2qUeSeHatZFe.70nfYkarSJHXiLo25wg2L8/hMj5hi.', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:34', 0, NULL),
(71, 'Usuario68', 'usuario68@correo.com', '$2y$12$8KVMcSkc2IxZQa0ZzuFIKOddVyKkzaqRxbBKOoLBafVwkzWLNkwHC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:34', 0, NULL),
(72, 'Usuario69', 'usuario69@correo.com', '$2y$12$e1kdm3PUnXAfYedTGgyKlO3Ep/KES5Z/AewagrIvDYP65d1MSsLBi', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:35', 0, NULL),
(73, 'Usuario70', 'usuario70@correo.com', '$2y$12$ZP0t6MqIuPpifSGA6aHhDecJnYbya.siNwJJwRIALoVUlgnAi9RDq', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:36', 0, NULL),
(74, 'Usuario71', 'usuario71@correo.com', '$2y$12$kwuxy8QAhs8qgWReXZSVIe3fa6.xaktJ7l0xXskK748kSZTB/fTFe', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:36', 0, NULL),
(75, 'Usuario72', 'usuario72@correo.com', '$2y$12$8X5N32io.Xs6nbWRgtCfde.81.q3PD8YzE6mCUHOQXpHTQN8pvkci', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:37', 0, NULL),
(76, 'Usuario73', 'usuario73@correo.com', '$2y$12$YDRtWR5//o4xK4pf8neZqOMc9IMi04NWP7uJFfiurCXFuOW3Zojh6', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:37', 0, NULL),
(77, 'Usuario74', 'usuario74@correo.com', '$2y$12$Scdq073R25k4.8gd0Q9s4e4qnyf4ezt0O7Ne/HnnCCbY1Imh8FIvi', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:38', 0, NULL),
(78, 'Usuario75', 'usuario75@correo.com', '$2y$12$k3KuRZ2WDfarl1JbrIAHfO/mM33D89Y0Blna.J1qO.eB2Psokrwou', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:39', 0, NULL),
(79, 'Usuario76', 'usuario76@correo.com', '$2y$12$kqqKIOQlP1Df1JZHBC8Vn.FxXs7A52WbGqhGYSndDwRvch9KJxUEW', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:39', 0, NULL),
(80, 'Usuario77', 'usuario77@correo.com', '$2y$12$KLpYq8WkKXhnWfIvmjvgX.EsXmypWzIFs9unzeK0OSf49/OdeG24i', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:40', 0, NULL),
(81, 'Usuario78', 'usuario78@correo.com', '$2y$12$d2c.FZ.lV/C51lOMi30.MedbMs.fMM.MeBbl/FTzthSN.BgnnP2di', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:41', 0, NULL),
(82, 'Usuario79', 'usuario79@correo.com', '$2y$12$dhWIK7pF98PQABvyo64/We22O4LPBjwcs.wZOHecJDKl/iTfF2Adq', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:42', 0, NULL),
(83, 'Usuario80', 'usuario80@correo.com', '$2y$12$5k04otaYqtw4KwMrejvLPurgwR2C8PgImamiImZW5TN0ukIRQZSL2', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:42', 0, NULL),
(84, 'Usuario81', 'usuario81@correo.com', '$2y$12$yPnnGEQqxTddoljCCaNyrOeqhoTCwL5eP5CMe.bTkwZPOl2tezLfK', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:42', 0, NULL),
(85, 'Usuario82', 'usuario82@correo.com', '$2y$12$XSKnZ.EP5ThiamwbupbwTe4/.DvwDlbIJ2CBUEfZ2WZIT2hsAv5FC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:43', 0, NULL),
(86, 'Usuario83', 'usuario83@correo.com', '$2y$12$WrmsZoFt.MNC2Dxk.qAYO.ypjGlDDUbIw.8kdBKUNIcAJlq89mgiy', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:43', 0, NULL),
(87, 'Usuario84', 'usuario84@correo.com', '$2y$12$.sVNentJAWKz2Cl/N2vH2e1nG5FODw.76So2J4uKEhm76TiP3oD86', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:44', 0, NULL),
(88, 'Usuario85', 'usuario85@correo.com', '$2y$12$TH0hDqk9PmJvIIiHZMFbc.ibUSeNCsSaTTGOwP2N8k2y2yzj2D/du', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:44', 0, NULL),
(89, 'Usuario86', 'usuario86@correo.com', '$2y$12$rAqN4DtcuMcM3TPwxHbnQu2l.NPd5TwZ.nAW6Y.ZPjufxvPC7rM.C', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:45', 0, NULL),
(90, 'Usuario87', 'usuario87@correo.com', '$2y$12$Q5MexKizBuhbUL69GuDZkekKbov3GivAYeGdWtaW1sQd.bZ338hKm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:45', 0, NULL),
(91, 'Usuario88', 'usuario88@correo.com', '$2y$12$NVVhnTvDIPlw/axdrPxr1.i11iEod2VZlc1/I0G9yc6RJXEeLv5Cu', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:46', 0, NULL),
(92, 'Usuario89', 'usuario89@correo.com', '$2y$12$Ff/9Pu.gkM/k7U698eoCTu4R8ZuIUawdnw8TdKQ7BS/uGuupSscby', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:46', 0, NULL),
(93, 'Usuario90', 'usuario90@correo.com', '$2y$12$9a5RO5Q7fQvachUg71zn8uaoo/eZQTMXvrjK60oceCiu3VPx1N8dy', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:47', 0, NULL),
(94, 'Usuario91', 'usuario91@correo.com', '$2y$12$wHfHFLUDHvAM7ciZF7X3F.CEiZ3MRVNx83YKAWEwnxyNs6.SKjug2', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:47', 0, NULL),
(95, 'Usuario92', 'usuario92@correo.com', '$2y$12$UmXxpJzRkbElcOTyTaiQz.Kbj7sAIJU83qHCkbSqiyA6kfFKNlRj6', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:48', 0, NULL),
(96, 'Usuario93', 'usuario93@correo.com', '$2y$12$gUOWpN767FyZfNkADfg5n.lCqip06UfRsHOkSwVoMSsMssvlBmh5y', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:48', 0, NULL),
(97, 'Usuario94', 'usuario94@correo.com', '$2y$12$56Z0j/naWog6Vnf9MxMP7eIkcYSfnfjpFGm2eY6RDYP0yem3ztvxG', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:49', 0, NULL),
(98, 'Usuario95', 'usuario95@correo.com', '$2y$12$BoQfm2HU4wiU2PSlHcnTxeXpI9lMwTGJZ4sZj37vNbuN.MEFku7cS', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:49', 0, NULL),
(99, 'Usuario96', 'usuario96@correo.com', '$2y$12$hnw5nMNKJh8SPG5jHDwANuzXTVUtPd89jCqwduOEVRV/kx15N7CFK', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:49', 0, NULL),
(100, 'Usuario97', 'usuario97@correo.com', '$2y$12$OVd.KGSYCq0vyfsJyLTZFuwDwU1oWXtMBCND5laFNJwv7JwWhN7sq', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:50', 0, NULL),
(101, 'Usuario98', 'usuario98@correo.com', '$2y$12$SihDkLA5LypD/WKc8uMqiO1CnIirKbX8JmI49pm4tB0TeVr1cPBSu', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:21:50', 0, NULL),
(102, 'Usuario99', 'usuario99@correo.com', '$2y$12$mAWP9i2wcF0woKqOg0Own.JM3p1vgowLuwq3JYzj/gFfKUKjXpmyS', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:21:51', 0, NULL),
(103, 'José Luis Herrera', 'josé.luis.herrera0@gmail.com', '$2y$12$ifIcCbAdhqjEhIFJr.u8Nu4U3prNxqqBh/3N1SDxVPk23y/zq.O5i', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:07', 0, NULL),
(104, 'Felipe Díaz', 'felipe.díaz1@hotmail.com', '$2y$12$TUIDLfVvXEIZpiRKlakEr.XTZCQxHw3Aoq9Aby2sQmOq3SEp4QSzu', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:07', 0, NULL),
(105, 'Sofía Méndez', 'sofía.méndez2@outlook.com', '$2y$12$QXrX36sZRF4yuVMqK3RXAuTEt73VF3pQdd/eLgOEQZxNvn2p59Hue', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:08', 0, NULL),
(106, 'Óscar Fernández', 'Óscar.fernández3@hotmail.com', '$2y$12$GtIupxj5mD8yYC54b/.EieOd8rhLzMOp19N1y7w.yRiwL4dnGbqkC', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:08', 0, NULL),
(107, 'David González', 'david.gonzález4@hotmail.com', '$2y$12$OfCOT.9voCZ/034m76.tXe5bgQQSyxsfJbLFuDLJLLV78ijYpNW5m', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:09', 0, NULL),
(108, 'Óscar Fernández', 'Óscar.fernández5@hotmail.com', '$2y$12$VY2HoRgj8kPDdfXAbskZ8uL7RWy5HDX1XQy.5YSHSv263PbJeRscm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:10', 0, NULL),
(109, 'Héctor Soto', 'héctor.soto6@hotmail.com', '$2y$12$bpH/b11FxO67lSVvb.7maeTyYFm6mFxoIWlCvdZ0nhpKch5JMd7GG', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:11', 0, NULL),
(110, 'Fernando Vargas', 'fernando.vargas7@yahoo.com', '$2y$12$jF8p5CsVCtcvCItKstG9P.HWyD0AxeQdFx/qGjsUSdZPhGbB02J5m', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:12', 0, NULL),
(111, 'Santiago Pérez', 'santiago.pérez8@outlook.com', '$2y$12$7f3S1i.0FuJ.SVPkz/sK0ubQ3wwCKDAhThRuQvf58V49.l52poT8y', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:12', 0, NULL),
(112, 'Carmen López', 'carmen.lópez9@gmail.com', '$2y$12$i3oOIq2bDkxVQZFUp2pduOq4pKyJjHNtyxoaedi8PaivueTeLP9wm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:13', 0, NULL),
(113, 'Santiago Pérez', 'santiago.pérez10@yahoo.com', '$2y$12$3qhUL1AadO2bw8MLQWWVV.RjbFcFC1RU0TrIYJPy6CuzZuSSR7qr6', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:13', 0, NULL),
(114, 'Camila González', 'camila.gonzález11@hotmail.com', '$2y$12$T/JUvkHk9pKmaghhQupPCOS1Ajo5saTqw2JwXLSztY/xy0WQf4uU6', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:14', 0, NULL),
(115, 'Camila González', 'camila.gonzález12@gmail.com', '$2y$12$UMc5TXo9/HUGAdEPdeOC1OIHxu7AXmY.p5yH04x7kdvAnw8YTOwtu', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:14', 0, NULL),
(116, 'Héctor Soto', 'héctor.soto13@hotmail.com', '$2y$12$z1JraxDGvoFq4SDLhb8wtunnThNe5Z.bOy1Up/kpIo6.KCRXphG1m', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:15', 0, NULL),
(117, 'José Luis Herrera', 'josé.luis.herrera14@icloud.com', '$2y$12$2T4C8iNugvrTB3yosPLGPe/O/qbLHgMmtak5Vfazlo6Bhmz.IpPLC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:16', 0, NULL),
(118, 'Marcos Ruiz', 'marcos.ruiz15@hotmail.com', '$2y$12$6NIyLye9AbKwie4Hc1yEpe7NI1khjR/Kvs0F9FBQ7HnENA/oPtrai', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:18', 0, NULL),
(119, 'Lucía Torres', 'lucía.torres16@icloud.com', '$2y$12$VI6L9.syFwrGMNn7FxYMLehyDmAcjrjYysceAlLSiG5JNqhDEtrl2', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:19', 0, NULL),
(120, 'Camila González', 'camila.gonzález17@yahoo.com', '$2y$12$00DLd5uNoztJRn4z0hI0TuHPNs2Fj2ROYOg1PiHnUWB2HseHs7EyK', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:20', 0, NULL),
(121, 'Violeta Castillo', 'violeta.castillo18@hotmail.com', '$2y$12$vxGKVsElczU/M2S6xP4UzOZyjgScxX8o3hx8K8Nt2jP1Jut3hpAAG', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:20', 0, NULL),
(122, 'Lucía Torres', 'lucía.torres19@icloud.com', '$2y$12$BCYfC/4XkWBGhkCQel7eoOf5LORykLgUdYwT7N.oxEACphdzoOG8e', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:21', 0, NULL),
(123, 'Isabella Morales', 'isabella.morales20@outlook.com', '$2y$12$TVicRiHxtig8doOTf81CDehEZbqRHtx2GGYpO/wvKVY9syZfiG6mO', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:22', 0, NULL),
(124, 'Gabriel López', 'gabriel.lópez21@hotmail.com', '$2y$12$pkZc8Mi6s2NcMcogEGyJGul6RtgDjzRzR46E3DtvOItWaSV2ybHgm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:22', 0, NULL),
(125, 'Mónica Navarro', 'mónica.navarro22@outlook.com', '$2y$12$RpOCAo4ExRISqqSAwCaHf.RkwdOgObh2AJO.jxBew3ikl.peb4wQW', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:23', 0, NULL),
(126, 'Santiago Pérez', 'santiago.pérez23@icloud.com', '$2y$12$dSo6.35gCRP3wnxlOOdNwuuxPTq5H0Y.s4nyvaA0Uko62bWPzvYmS', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:23', 0, NULL),
(127, 'Juan Pablo García', 'juan.pablo.garcía24@yahoo.com', '$2y$12$bHkwGbj5G6BiiIi7E1.2EOH9MQvSTyDFsOSrdBLvgwnHnh8LeZ/qm', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:24', 0, NULL),
(128, 'Lina Navarro', 'lina.navarro25@gmail.com', '$2y$12$Hk3mjwkk7gv8s71D3M/IQ.x8QhNCNNVWWFulRnA6HepUfM0D63znS', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:25', 0, NULL),
(129, 'David González', 'david.gonzález26@yahoo.com', '$2y$12$QpROBE/a1XrUAJSHe7R2vOm7k/YaRqvXGEVZx5zIaNCuJ7QIZsVXW', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:26', 0, NULL),
(130, 'Violeta Castillo', 'violeta.castillo27@hotmail.com', '$2y$12$99a.nW9UVchxgT0vJ9cpaeLNdDL0ABoY3fK4HjYiiBvxHdMRaBP9e', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:27', 0, NULL),
(131, 'Carla Jiménez', 'carla.jiménez28@outlook.com', '$2y$12$NCCr4WjSCOxfqSINCBqvm.oG8a6IjLrUlKfcdAT1iugRrf/V5W8lG', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:28', 0, NULL),
(132, 'Óscar Fernández', 'Óscar.fernández29@yahoo.com', '$2y$12$9aybEXiyzGdbbVP1yRhLG.kkQaEzEa3.gJnRqV0FD/ygx9qHLCTYC', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:30', 0, NULL),
(133, 'Valentina Álvarez', 'valentina.Álvarez30@yahoo.com', '$2y$12$tpTkd1BhbkvZthA39WPfCOO90yagf7pTrLu6m3KE4/iORllsikHz.', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:31', 0, NULL),
(134, 'Cristian García', 'cristian.garcía31@outlook.com', '$2y$12$s40Z/N.2.aK6TetHyEQ7g.dvmeAyz64y6yJ1F/pMnbt9mLvVPXW6K', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:32', 0, NULL),
(135, 'Camila González', 'camila.gonzález32@hotmail.com', '$2y$12$LxYTymXa7FMMp6N082MKteHyebTiejmvAz/LEBHlyPUZ5JPDcmzF2', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:32', 0, NULL),
(136, 'Adriana Ruiz', 'adriana.ruiz33@icloud.com', '$2y$12$cG6Xo1s7UqWAH20yKOG.nuJ5qKmy/sVcfaWTO0jMFKWkS0Jb7710m', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:33', 0, NULL),
(137, 'Mónica Navarro', 'mónica.navarro34@hotmail.com', '$2y$12$n0oIWDGO9H0kN7ZT.JaHoehkTWXbysHA0NhDwnN6I1pmuss4jKcei', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:34', 0, NULL),
(138, 'Marcos Ruiz', 'marcos.ruiz35@gmail.com', '$2y$12$fzq40YlOrkgMmtAlD/j36Otb8ilkcTR.8XGfi3jq1qiqBXr1eg/dO', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:34', 0, NULL),
(139, 'Lucía Torres', 'lucía.torres36@icloud.com', '$2y$12$lYFKlKpCnrIpkOMmx.TJ7OqALGIDPxfF3Iz.hom.MgqPUldCVOvXO', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:35', 0, NULL),
(140, 'Fernando Vargas', 'fernando.vargas37@outlook.com', '$2y$12$cZNHD9MSSo98KRO8jmB4nuzKkbhsRgVs4BWMKQSPCVHavqcKOD44u', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:36', 0, NULL),
(141, 'Elías Romero', 'elías.romero38@icloud.com', '$2y$12$vvof58m0/CQvIFG8n3/1RO/Hjz4OnWRt.aak5JNM20/naSnlUY6Ou', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:36', 0, NULL),
(142, 'Juan Pablo García', 'juan.pablo.garcía39@gmail.com', '$2y$12$YJgSNmDKk4KPzS0rDzJOfOYy5H2hWBPm9nGTIwGJMPob0JilFzz9m', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:36', 0, NULL),
(143, 'Lina Navarro', 'lina.navarro40@yahoo.com', '$2y$12$ljUblZl1FyEL7VppocF4POtURFikBV3UfXmCtFUOwWZjBiPEYPKs.', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:37', 0, NULL),
(144, 'Valentina Álvarez', 'valentina.Álvarez41@gmail.com', '$2y$12$../QU3aMKqlS3UcAwkhde.rt31e50XigryHlZelY0dCOj/0potiCG', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:37', 0, NULL),
(145, 'Violeta Castillo', 'violeta.castillo42@outlook.com', '$2y$12$w4nFgaEDEFUaNYo/x4C6tOrW7F.7G1xhKZHl6cwulACt.mzAGmibG', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:38', 0, NULL),
(146, 'Camila González', 'camila.gonzález43@gmail.com', '$2y$12$0pEEFDqR7wu6m.mJ0fWocuwutVefTy0C3EuISahwr7se/XMGSVdYK', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:38', 0, NULL),
(147, 'Ricardo Sánchez', 'ricardo.sánchez44@icloud.com', '$2y$12$kt17kKd5Cc.BVmNeeLWiPeHAajWfgLPkwhGB9BSQN2lb/eaauxMOi', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:39', 0, NULL),
(148, 'Sara Salazar', 'sara.salazar45@icloud.com', '$2y$12$g4ovCApE4Zu5TI3FghCk4eq7xWZyoslDOeILDqioiDtSJ39lctTJG', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:39', 0, NULL),
(149, 'Violeta Castillo', 'violeta.castillo46@outlook.com', '$2y$12$qtsf.hvsWkaKZdO6.kC8mOtZIQSpgyYj5jKrz5BNt08gLn1/ywcWe', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:39', 0, NULL),
(150, 'Mónica Navarro', 'mónica.navarro47@gmail.com', '$2y$12$///9ugv7T8/QyiTEpJLMZOjATds9wFN9fpoNagnjlyo0iGAwl1wOe', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:40', 0, NULL),
(151, 'Camila González', 'camila.gonzález48@outlook.com', '$2y$12$m2YourPFFqSO4ia30aggneR5hAfD3cIprj5I8HB.vKW4OO.hCZTiC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:40', 0, NULL),
(152, 'Isabella Morales', 'isabella.morales49@outlook.com', '$2y$12$ZEBwlC90E2KtENcZi2bq7uHhGSgDcUpictKtF8CkcE5Np9UafjpE6', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:41', 0, NULL),
(153, 'Carmen López', 'carmen.lópez50@gmail.com', '$2y$12$9H5ZvPzHxAEKrwkoFMpy6O7yBrullS49hTqPWOdyvt1cM1yAcN5mm', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:41', 0, NULL),
(154, 'Lucía Torres', 'lucía.torres51@yahoo.com', '$2y$12$JOpx8o8vUI.eEGhyQosk8uY7TrjiQDzddVDzcGokXTQV2F5BD1wbm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:42', 0, NULL),
(155, 'Fernando Vargas', 'fernando.vargas52@icloud.com', '$2y$12$Ffcict5FCnpfUwObJ8AqJ.CPehXsZKbrLLSZe1B75rk.1CagWPPQC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:42', 0, NULL),
(156, 'Cristian García', 'cristian.garcía53@icloud.com', '$2y$12$bDLCRbPSx5o32To4Qh1MXeBal0YXa.o9k3Ekh6MTrovRP0RJxykfG', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:42', 0, NULL),
(157, 'David González', 'david.gonzález54@yahoo.com', '$2y$12$wdq1aFLLNhnRS6EbfbBj4eD4XCiXoftH7WW5sr..6KmZi31gO7Ir6', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:43', 0, NULL),
(158, 'Óscar Fernández', 'Óscar.fernández55@icloud.com', '$2y$12$.HN0c2astdvUVq1Pm5pjgue3x8txmw3z37NdTZLehtjlEOrNtLnVe', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:44', 0, NULL),
(159, 'Sara Salazar', 'sara.salazar56@yahoo.com', '$2y$12$dEq4eJcPFtg.14azQdjQ/O3yQRVhOSShMZzfi1fcC9sp0B76noNd6', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:44', 0, NULL),
(160, 'Cristian García', 'cristian.garcía57@gmail.com', '$2y$12$8ailqX3kigkVriLHQSx7sebpa2DksnBQqsPm4DfFD8fUJjOqJCmnW', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:45', 0, NULL),
(161, 'Raúl Sánchez', 'raúl.sánchez58@yahoo.com', '$2y$12$3vvKCOKepG/ZFLOBoRIQ6uqieNmTmD3uoCxeVQPMYHu6j1F6dzanO', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:45', 0, NULL),
(162, 'David González', 'david.gonzález59@icloud.com', '$2y$12$Bvt8tmgg37Urtt89Ithbse/0rIeKwbHqq04mW6l2PwMTkMD65hn9e', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:46', 0, NULL),
(163, 'Carla Jiménez', 'carla.jiménez60@gmail.com', '$2y$12$WJHpAlxEkX5UJYjtsv4li.mtAoG/PS1TPpsXkucQp/tH7DRG.OBmO', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:46', 0, NULL),
(164, 'Lucía Torres', 'lucía.torres61@outlook.com', '$2y$12$x/NWQm06OFDkoAy75FjHUe9yk3YDcpWXnk.boh..H6W0prQduzyya', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:47', 0, NULL),
(165, 'Natalia Romero', 'natalia.romero62@hotmail.com', '$2y$12$UfelwUePSE/G2PqnumYIVu9xTJRomBdeOdlqSlmyoCOAIB9PFrmWW', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:47', 0, NULL),
(166, 'Lucía Torres', 'lucía.torres63@hotmail.com', '$2y$12$kKo03fexid9d2vxFS/4LS.w5ayyujIGWG0iamBMfZKCxZoI6JnmNa', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:48', 0, NULL),
(167, 'Sara Salazar', 'sara.salazar64@outlook.com', '$2y$12$BAjAas6WDEg0HV0qBPi/TOtyKpctHcs4Lji5lDLCKQzpYYAgFSkWa', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:48', 0, NULL),
(168, 'Sofía Méndez', 'sofía.méndez65@icloud.com', '$2y$12$wQ3NsM3AG1eTjgk9pFHKrelv2Quxm08gg3uyrvTPzweeFgzDengay', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:48', 0, NULL),
(169, 'Carla Jiménez', 'carla.jiménez66@hotmail.com', '$2y$12$JnopKh5WasZN1MC9O2kl/eG7EC62KDKoaeUUv7.zH07yL8rIV2PR6', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:49', 0, NULL),
(170, 'Santiago Pérez', 'santiago.pérez67@gmail.com', '$2y$12$HbRItc4S0VkijhJOV760xuIVBvezXyD/qwTWzF9Y6es8lI0MAD2wm', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:49', 0, NULL),
(171, 'Paula Fernández', 'paula.fernández68@yahoo.com', '$2y$12$9ZM7ZYea/4R3SrYzLwUqEuR5AZjY0lsMYz6nTk1oLfUuV4k46R/DO', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:50', 0, NULL),
(172, 'Lucía Torres', 'lucía.torres69@yahoo.com', '$2y$12$GUWpWnT2v7INnvxVRhlmYuR4JmRAJOjS2bbwi0xsMX3.mg2AErnBW', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:50', 0, NULL),
(173, 'Óscar Fernández', 'Óscar.fernández70@gmail.com', '$2y$12$f/f/p3uWZ33jDUWRrpjMre5Vm38cVSxvMt.WEYS0W9EmOy/vtnfmC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:51', 0, NULL),
(174, 'Ricardo Sánchez', 'ricardo.sánchez71@gmail.com', '$2y$12$xL8V5L0X0VkZXPfTTyicgOcxWmV42mqY5oEvHqk1cRQ95dk4lFbJO', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:51', 0, NULL),
(175, 'Violeta Castillo', 'violeta.castillo72@icloud.com', '$2y$12$Cmd./0KJGalxF5m9U6/Y8ugW5Wn5xa1vwQSabWNQ6KHhHiT2pcaTm', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:51', 0, NULL),
(176, 'Adriana Ruiz', 'adriana.ruiz73@hotmail.com', '$2y$12$ZZngQpur8TZEsiw.6AzDl.dDHf2hISVT3vfblO.AlwiibOVNwX9t6', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:52', 0, NULL),
(177, 'Camila González', 'camila.gonzález74@gmail.com', '$2y$12$k.dELAkpqSdIgNNqae6uZuWRTj2LxXk3JlD1xPRQEIV9weoP9rNh6', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:52', 0, NULL),
(178, 'Sara Salazar', 'sara.salazar75@outlook.com', '$2y$12$HcVklwyQbOOi0qAiIEEjs.H8wXHoxsLAFVr5LKk5UfacZ2aEbPvbC', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:53', 0, NULL),
(179, 'Sara Salazar', 'sara.salazar76@icloud.com', '$2y$12$/P9/VIE3b1/9PFm1VXAqSecDzBFTqLL7yKR9txYwEVB9LqMDOh2XK', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:53', 0, NULL),
(180, 'Paula Fernández', 'paula.fernández77@outlook.com', '$2y$12$01Z1EVlXq5XMVGAveo/zFe2V1pGOONLc2AuzzMR6fO6cvs3GwGE..', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:54', 0, NULL),
(181, 'Ricardo Sánchez', 'ricardo.sánchez78@gmail.com', '$2y$12$ku6TicalmxfohuymkpPIwOCA0ExxxCirLuHphmMnb1FjxXnJLTrsO', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:54', 0, NULL),
(182, 'Santiago Pérez', 'santiago.pérez79@outlook.com', '$2y$12$Xzp0ACmir34Gw6hf2fyPK.r1iAvKLWqT.O.bZu7v7qM1WBU6x//r2', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:54', 0, NULL),
(183, 'Ricardo Sánchez', 'ricardo.sánchez80@icloud.com', '$2y$12$zyUQqRXjOxMt9MFgEyEON.Sz6xEXpoDUcdQ9EcOsuY5vfxCM4x6n2', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:55', 0, NULL),
(184, 'Paula Fernández', 'paula.fernández81@gmail.com', '$2y$12$utrXgta820Zfo/cZHhrB8eLJNely92uwUxopjY0RXEHWAy65d8hYa', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:55', 0, NULL),
(185, 'Carla Jiménez', 'carla.jiménez82@yahoo.com', '$2y$12$y2osj8Z2lOs4xXDy3zgzHOQQJDtFvQi/HLskj9lUJR95/yHI4M1lO', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:56', 0, NULL),
(186, 'Santiago Pérez', 'santiago.pérez83@outlook.com', '$2y$12$YyHULmj0KiD7kF7Hwg70ZuZPy1VahB8lBpBOlQq3zm3GPE0lJnqq6', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:56', 0, NULL),
(187, 'Violeta Castillo', 'violeta.castillo84@icloud.com', '$2y$12$QdrfWIAz0c1mab3TjtzuBunEdii4sdmxOCba3Z8WBpNiFc6oOzst6', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:56', 0, NULL),
(188, 'Mónica Navarro', 'mónica.navarro85@yahoo.com', '$2y$12$Ss3IdNLj5zYJJIKwa.un5u9WM9h3KelyIAcb0Fa3LIyuJ3VjL7P6y', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:57', 0, NULL),
(189, 'Mónica Navarro', 'mónica.navarro86@icloud.com', '$2y$12$yNmm4hHBE81unzovL04x3OsTFW5yFGlapvNZRn1FlC6J/QBs3ctb.', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:57', 0, NULL),
(190, 'Camila González', 'camila.gonzález87@hotmail.com', '$2y$12$Sg6aZ8ut4XqxLjGNGDyhz.WjNmpwg1BNjHRFNeltjgN1Dv.nZphnG', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:58', 0, NULL),
(191, 'David González', 'david.gonzález88@hotmail.com', '$2y$12$.WM3Vbz.fUPs6RgPuIBXFOUcogbRtHGlsrPbW54A4dN88oTcfxoea', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:58', 0, NULL),
(192, 'Sofía Méndez', 'sofía.méndez89@yahoo.com', '$2y$12$cmGIP1edVhjAmmzhz9r2pu5R.ZJcr9IT2XLCnjWLALU7wVKJgdbsq', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:59', 0, NULL),
(193, 'Sara Salazar', 'sara.salazar90@gmail.com', '$2y$12$pvKVtK8n7giN8MOfbmpDpOK5vft7bJtXo1o.44BgDqNvS7QG.Nmfy', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:24:59', 0, NULL),
(194, 'Valentina Álvarez', 'valentina.Álvarez91@yahoo.com', '$2y$12$sIl7.McslVy6PeDIhCm/L.2ELS2iMNqXBOntMhQVHGLcsaConj2ja', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:24:59', 0, NULL),
(195, 'Violeta Castillo', 'violeta.castillo92@hotmail.com', '$2y$12$c8gzgxoNdxxFJ3wbPz1yqeGAHngDB9IpaaHX0CQn1YRTzCLs3vigq', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:25:00', 0, NULL),
(196, 'Juan Pablo García', 'juan.pablo.garcía93@hotmail.com', '$2y$12$SF5T8OsWgEBhc3/DkCUcd.fquDCs4M7tn72ngtlVu0rqWuZ7jQie2', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:25:00', 0, NULL),
(197, 'Marcos Ruiz', 'marcos.ruiz94@outlook.com', '$2y$12$Y9k1lLW1LDaf1uJRDcpm9.aPllV1y/HUheDnD37XprtuJTVoIDhNS', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:25:01', 0, NULL),
(198, 'Raúl Sánchez', 'raúl.sánchez95@hotmail.com', '$2y$12$wLTpbLwjyYjCpg5Cc/jG.eAajKRzOqVD7MBICgnCt19bRpY8uXe9C', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:25:01', 0, NULL),
(199, 'Juan Pablo García', 'juan.pablo.garcía96@gmail.com', '$2y$12$mUfNVa8PFJD4VtZUkKzv9ef6Lznp9DPtS1gwaS05ll4PE8EJ87CVm', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:25:01', 0, NULL),
(200, 'Claudia Martínez', 'claudia.martínez97@gmail.com', '$2y$12$FhxDeSBZUwgy0pRzkqIvU.PVST1caxl9/EVBAExK95l9Cdupc9KKu', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:25:02', 0, NULL),
(201, 'Sara Salazar', 'sara.salazar98@icloud.com', '$2y$12$m3rqZ4bMSUKaro7hbFHPKOxr2yiU22xuG.D2ehHLR.J5JqBxao/vC', 'Administrador', '', '0000-00-00', '', '2025-02-05 02:25:02', 0, NULL),
(202, 'Santiago Pérez', 'santiago.pérez99@gmail.com', '$2y$12$3ZKGLbvgsBgMddeLwHTJ4unKcAchDtCx62w/59sTt/IYYzqyJt6Qu', 'Usuario', '', '0000-00-00', '', '2025-02-05 02:25:03', 0, NULL),
(203, 'Iris', 'ic8281932@gmail.com', '$2a$10$SKahzrtut.GUAxnSxYZQx.Qzc/r1gAPtzh7V7d00xQMkELOmQyhg2', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739421355612-912265171.jpg', '2009-09-09', 'Femenino', '2025-02-13 04:35:56', 0, NULL),
(205, 'Iris', 'ic8281933@gmail.com', '$2a$10$5FebWunMgEsfYz/n66BJoOl8lreyEZxU0/2NknblHwqJkViGcItYu', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739422194620-220925475.jpg', '2009-09-09', 'Femenino', '2025-02-13 04:49:54', 0, NULL),
(207, 'Iris Jaqueline', 'ic8281934@gmail.com', '$2a$10$Nzy2a6HEtCYl90ACMn0IVetCWJWL6nOeqtPECBXMXxc7PypagTFVO', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739422484805-645435018.jpg', '2009-09-09', 'Femenino', '2025-02-13 04:54:45', 0, NULL),
(209, 'Iris', 'ic8281935@gmail.com', '$2a$10$AWvhf8/rEiEqdJ7gqQQf5uYxdJKtV5T7lT7155PgLwc5KLukXobtm', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739422806190-810662441.jpg', '2009-09-09', 'Femenino', '2025-02-13 05:00:06', 0, NULL),
(210, 'Iris', 'ic8281936@gmail.com', '$2a$10$NeMGcgK6cTQ1GGit3DquGOa9I9JRNmc0WcQ1Pgb.W5vABaauqIXlW', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739423498327-81480625.png', '2009-09-09', 'Femenino', '2025-02-13 05:11:38', 0, NULL),
(211, 'Iris', 'ic8281937@gmail.com', '$2a$10$giKUYfliJS2L7P4FJNfC2O/dr5dXZ.JQ.YD3inbmr6l1iuXTWONzW', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739430675671-448903063.jpg', '2009-09-09', 'Femenino', '2025-02-13 07:11:16', 0, NULL),
(212, 'Iris', 'ic8281938@gmail.com', '$2a$10$YCb8rnI45G2zPYZH/sjP8.mxIHcEQYwEXHOormhwu.v4ndhzokIM.', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739432877350-732907011.png', '2005-09-09', 'Femenino', '2025-02-13 07:47:57', 0, NULL),
(213, 'Iris', 'ic8281939@gmail.com', '$2a$10$8AuefPdk8mGCTs4E81lglO4DKMNld9fntfovEhIg1/oMhe9aAViV.', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739452312349-402674019.jpg', '2004-09-09', 'Femenino', '2025-02-13 13:11:52', 0, NULL),
(214, 'Iris', 'ic82819300@gmail.com', '$2a$10$p5s1A6ScfI6nsqCWzsshmeRE/gusQOUd7kwC9PeuA4j5qvi5K9zwm', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739476378440-7535865.jpg', '2005-09-09', 'Femenino', '2025-02-13 19:52:58', 0, NULL),
(215, 'Iris', 'ic82819310@gmail.com', '$2a$10$86PrBQpijOAPoT.d1ViRde/mXQfbuagB.m45E/Kh8XFMn.mzW3tVO', 'Administrador', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739477576191-822466767.jpg', '2005-09-09', 'Femenino', '2025-02-13 20:12:56', 0, NULL),
(216, 'cesar', 'Leo@gmail.com', '$2a$10$LVKmhoh1mfc5hASz04iREuaaB7pf9OBof.PLmrMvdnSEUCERgkoLO', 'Usuario', 'C:\\Users\\Iris\\proyecto_api\\uploads\\foto-1739478096992-148350135.jpg', '2005-09-09', 'Masculino', '2025-02-13 20:21:37', 0, NULL);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `valvulas`
--

CREATE TABLE `valvulas` (
  `id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `ubicacion` varchar(100) DEFAULT NULL,
  `estado` enum('Abierta','Cerrada') DEFAULT 'Cerrada',
  `fecha_instalacion` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `valvulas`
--

INSERT INTO `valvulas` (`id`, `nombre`, `ubicacion`, `estado`, `fecha_instalacion`) VALUES
(1, 'Valvula1', 'Zona A', 'Cerrada', '2025-01-29 04:14:55'),
(2, 'Valvula2', 'Zona B', 'Abierta', '2025-01-29 04:14:55'),
(3, 'Válvula 1', 'Zona B', 'Abierta', '2024-09-13 08:40:56'),
(4, 'Válvula 2', 'Zona B', 'Abierta', '2024-12-26 08:40:56'),
(5, 'Válvula 3', 'Zona A', 'Cerrada', '2024-10-17 08:40:56'),
(6, 'Válvula 4', 'Zona A', 'Abierta', '2024-08-29 08:40:57'),
(7, 'Válvula 5', 'Zona B', 'Abierta', '2024-11-17 08:40:57'),
(8, 'Válvula 6', 'Zona B', 'Cerrada', '2025-01-05 08:40:57'),
(9, 'Válvula 7', 'Zona B', 'Cerrada', '2024-02-10 08:40:57'),
(10, 'Válvula 8', 'Zona B', 'Abierta', '2024-05-18 08:40:57'),
(11, 'Válvula 9', 'Zona B', 'Abierta', '2024-04-03 08:40:57'),
(12, 'Válvula 10', 'Zona B', 'Abierta', '2024-02-07 08:40:57'),
(13, 'Válvula 11', 'Zona B', 'Cerrada', '2024-04-21 08:40:57'),
(14, 'Válvula 12', 'Zona A', 'Cerrada', '2024-02-18 08:40:57'),
(15, 'Válvula 13', 'Zona A', 'Abierta', '2024-05-18 08:40:57'),
(16, 'Válvula 14', 'Zona A', 'Abierta', '2024-05-13 08:40:57'),
(17, 'Válvula 15', 'Zona A', 'Cerrada', '2024-07-21 08:40:57'),
(18, 'Válvula 16', 'Zona A', 'Abierta', '2024-09-05 08:40:57'),
(19, 'Válvula 17', 'Zona A', 'Abierta', '2024-07-22 08:40:57'),
(20, 'Válvula 18', 'Zona B', 'Cerrada', '2024-09-05 08:40:57'),
(21, 'Válvula 19', 'Zona B', 'Abierta', '2024-08-20 08:40:58'),
(22, 'Válvula 20', 'Zona B', 'Cerrada', '2024-03-23 08:40:58'),
(23, 'Válvula 21', 'Zona B', 'Abierta', '2024-06-29 08:40:58'),
(24, 'Válvula 22', 'Zona B', 'Cerrada', '2025-01-26 08:40:58'),
(25, 'Válvula 23', 'Zona A', 'Cerrada', '2024-07-19 08:40:58'),
(26, 'Válvula 24', 'Zona A', 'Abierta', '2024-02-15 08:40:58'),
(27, 'Válvula 25', 'Zona B', 'Abierta', '2024-08-31 08:40:58'),
(28, 'Válvula 26', 'Zona A', 'Abierta', '2024-10-15 08:40:58'),
(29, 'Válvula 27', 'Zona A', 'Cerrada', '2024-07-18 08:40:58'),
(30, 'Válvula 28', 'Zona A', 'Cerrada', '2024-05-02 08:40:58'),
(31, 'Válvula 29', 'Zona A', 'Cerrada', '2024-08-14 08:40:59'),
(32, 'Válvula 30', 'Zona A', 'Cerrada', '2024-10-31 08:40:59'),
(33, 'Válvula 31', 'Zona A', 'Cerrada', '2025-01-13 08:40:59'),
(34, 'Válvula 32', 'Zona A', 'Cerrada', '2024-03-01 08:40:59'),
(35, 'Válvula 33', 'Zona B', 'Cerrada', '2024-09-04 08:40:59'),
(36, 'Válvula 34', 'Zona A', 'Abierta', '2024-08-16 08:40:59'),
(37, 'Válvula 35', 'Zona B', 'Cerrada', '2024-06-13 08:40:59'),
(38, 'Válvula 36', 'Zona A', 'Cerrada', '2024-08-02 08:40:59'),
(39, 'Válvula 37', 'Zona B', 'Abierta', '2024-07-30 08:40:59'),
(40, 'Válvula 38', 'Zona A', 'Abierta', '2024-08-25 08:40:59'),
(41, 'Válvula 39', 'Zona B', 'Abierta', '2024-10-10 08:40:59'),
(42, 'Válvula 40', 'Zona B', 'Abierta', '2024-11-29 08:40:59'),
(43, 'Válvula 41', 'Zona B', 'Abierta', '2024-05-11 08:40:59'),
(44, 'Válvula 42', 'Zona B', 'Abierta', '2024-09-13 08:40:59'),
(45, 'Válvula 43', 'Zona B', 'Cerrada', '2024-04-14 08:40:59'),
(46, 'Válvula 44', 'Zona A', 'Abierta', '2024-07-01 08:40:59'),
(47, 'Válvula 45', 'Zona A', 'Abierta', '2025-01-14 08:40:59'),
(48, 'Válvula 46', 'Zona A', 'Abierta', '2024-12-15 08:40:59'),
(49, 'Válvula 47', 'Zona B', 'Cerrada', '2025-02-02 08:40:59'),
(50, 'Válvula 48', 'Zona B', 'Cerrada', '2024-08-11 08:41:00'),
(51, 'Válvula 49', 'Zona B', 'Abierta', '2024-11-10 08:41:00'),
(52, 'Válvula 50', 'Zona A', 'Abierta', '2024-07-07 08:41:00'),
(53, 'Válvula 51', 'Zona B', 'Cerrada', '2025-01-19 08:41:00'),
(54, 'Válvula 52', 'Zona A', 'Abierta', '2025-01-04 08:41:00'),
(55, 'Válvula 53', 'Zona A', 'Cerrada', '2024-05-22 08:41:00'),
(56, 'Válvula 54', 'Zona B', 'Cerrada', '2024-09-29 08:41:00'),
(57, 'Válvula 55', 'Zona A', 'Abierta', '2024-06-23 08:41:00'),
(58, 'Válvula 56', 'Zona B', 'Cerrada', '2025-01-28 08:41:00'),
(59, 'Válvula 57', 'Zona A', 'Abierta', '2024-03-22 08:41:00'),
(60, 'Válvula 58', 'Zona A', 'Cerrada', '2025-01-28 08:41:00'),
(61, 'Válvula 59', 'Zona B', 'Abierta', '2024-03-20 08:41:00'),
(62, 'Válvula 60', 'Zona B', 'Cerrada', '2024-05-21 08:41:00'),
(63, 'Válvula 61', 'Zona B', 'Abierta', '2024-02-19 08:41:00'),
(64, 'Válvula 62', 'Zona B', 'Cerrada', '2024-02-13 08:41:01'),
(65, 'Válvula 63', 'Zona A', 'Cerrada', '2024-12-14 08:41:01'),
(66, 'Válvula 64', 'Zona B', 'Cerrada', '2024-08-30 08:41:01'),
(67, 'Válvula 65', 'Zona A', 'Abierta', '2024-08-14 08:41:01'),
(68, 'Válvula 66', 'Zona A', 'Abierta', '2025-01-08 08:41:01'),
(69, 'Válvula 67', 'Zona B', 'Cerrada', '2024-09-08 08:41:01'),
(70, 'Válvula 68', 'Zona A', 'Abierta', '2024-04-11 08:41:01'),
(71, 'Válvula 69', 'Zona A', 'Abierta', '2025-02-03 08:41:01'),
(72, 'Válvula 70', 'Zona B', 'Cerrada', '2024-08-30 08:41:01'),
(73, 'Válvula 71', 'Zona B', 'Abierta', '2024-11-17 08:41:01'),
(74, 'Válvula 72', 'Zona B', 'Abierta', '2024-09-30 08:41:01'),
(75, 'Válvula 73', 'Zona A', 'Abierta', '2024-02-06 08:41:01'),
(76, 'Válvula 74', 'Zona B', 'Cerrada', '2024-04-06 08:41:01'),
(77, 'Válvula 75', 'Zona B', 'Abierta', '2024-03-15 08:41:01'),
(78, 'Válvula 76', 'Zona A', 'Abierta', '2024-09-05 08:41:01'),
(79, 'Válvula 77', 'Zona A', 'Abierta', '2024-07-27 08:41:01'),
(80, 'Válvula 78', 'Zona A', 'Cerrada', '2025-01-26 08:41:01'),
(81, 'Válvula 79', 'Zona B', 'Abierta', '2024-08-27 08:41:01'),
(82, 'Válvula 80', 'Zona A', 'Cerrada', '2024-03-16 08:41:01'),
(83, 'Válvula 81', 'Zona A', 'Abierta', '2024-07-01 08:41:01'),
(84, 'Válvula 82', 'Zona B', 'Cerrada', '2024-10-26 08:41:01'),
(85, 'Válvula 83', 'Zona A', 'Cerrada', '2024-04-16 08:41:02'),
(86, 'Válvula 84', 'Zona B', 'Cerrada', '2024-07-18 08:41:02'),
(87, 'Válvula 85', 'Zona B', 'Abierta', '2024-03-17 08:41:02'),
(88, 'Válvula 86', 'Zona A', 'Cerrada', '2025-01-19 08:41:02'),
(89, 'Válvula 87', 'Zona B', 'Cerrada', '2024-10-14 08:41:02'),
(90, 'Válvula 88', 'Zona A', 'Abierta', '2024-05-13 08:41:02'),
(91, 'Válvula 89', 'Zona B', 'Abierta', '2025-01-30 08:41:02'),
(92, 'Válvula 90', 'Zona A', 'Abierta', '2024-09-14 08:41:02'),
(93, 'Válvula 91', 'Zona A', 'Cerrada', '2024-03-22 08:41:03'),
(94, 'Válvula 92', 'Zona B', 'Cerrada', '2024-08-19 08:41:03'),
(95, 'Válvula 93', 'Zona A', 'Abierta', '2024-08-22 08:41:03'),
(96, 'Válvula 94', 'Zona A', 'Cerrada', '2024-11-30 08:41:03'),
(97, 'Válvula 95', 'Zona A', 'Abierta', '2024-11-16 08:41:03'),
(98, 'Válvula 96', 'Zona B', 'Cerrada', '2024-05-13 08:41:03'),
(99, 'Válvula 97', 'Zona A', 'Cerrada', '2024-11-04 08:41:03'),
(100, 'Válvula 98', 'Zona B', 'Cerrada', '2024-06-15 08:41:03'),
(101, 'Válvula 99', 'Zona A', 'Abierta', '2024-03-07 08:41:03'),
(102, 'Válvula 100', 'Zona B', 'Cerrada', '2024-08-20 08:41:04');

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `alertas`
--
ALTER TABLE `alertas`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `configuraciones_riego`
--
ALTER TABLE `configuraciones_riego`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `registros_sensores`
--
ALTER TABLE `registros_sensores`
  ADD PRIMARY KEY (`id`),
  ADD KEY `sensor_id` (`sensor_id`);

--
-- Indices de la tabla `riegos`
--
ALTER TABLE `riegos`
  ADD PRIMARY KEY (`id`),
  ADD KEY `valvula_id` (`valvula_id`);

--
-- Indices de la tabla `sensores`
--
ALTER TABLE `sensores`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `correo` (`correo`);

--
-- Indices de la tabla `valvulas`
--
ALTER TABLE `valvulas`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `alertas`
--
ALTER TABLE `alertas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=103;

--
-- AUTO_INCREMENT de la tabla `configuraciones_riego`
--
ALTER TABLE `configuraciones_riego`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=103;

--
-- AUTO_INCREMENT de la tabla `registros_sensores`
--
ALTER TABLE `registros_sensores`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=103;

--
-- AUTO_INCREMENT de la tabla `riegos`
--
ALTER TABLE `riegos`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=103;

--
-- AUTO_INCREMENT de la tabla `sensores`
--
ALTER TABLE `sensores`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=103;

--
-- AUTO_INCREMENT de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=217;

--
-- AUTO_INCREMENT de la tabla `valvulas`
--
ALTER TABLE `valvulas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=103;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `alertas`
--
ALTER TABLE `alertas`
  ADD CONSTRAINT `alertas_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `configuraciones_riego`
--
ALTER TABLE `configuraciones_riego`
  ADD CONSTRAINT `configuraciones_riego_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `registros_sensores`
--
ALTER TABLE `registros_sensores`
  ADD CONSTRAINT `registros_sensores_ibfk_1` FOREIGN KEY (`sensor_id`) REFERENCES `sensores` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `riegos`
--
ALTER TABLE `riegos`
  ADD CONSTRAINT `riegos_ibfk_1` FOREIGN KEY (`valvula_id`) REFERENCES `valvulas` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
