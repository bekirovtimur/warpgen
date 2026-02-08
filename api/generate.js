import nacl from "tweetnacl";
import { Buffer } from "buffer";

/**
 * Клиент для работы с API Cloudflare WARP
 */
class CloudflareWarpClient {
  static BASE_URL = 'https://api.cloudflareclient.com/v0i1909051800';
  static DEFAULT_HEADERS = {
    'User-Agent': 'okhttp/3.12.1',
    'Content-Type': 'application/json',
  };

  async registerClient(publicKey) {
    const requestBody = {
      install_id: '',
      tos: new Date().toISOString(),
      key: publicKey,
      fcm_token: '',
      type: 'ios',
      locale: 'en_US',
    };

    const response = await this.makeRequest('POST', 'reg', requestBody);
    
    if (!response.result?.id || !response.result?.token) {
      throw new Error('Invalid registration response structure');
    }

    return {
      id: response.result.id,
      token: response.result.token,
    };
  }

  async enableWarp(clientId, token) {
    const headers = {
      ...CloudflareWarpClient.DEFAULT_HEADERS,
      'Authorization': `Bearer ${token}`,
    };

    const response = await this.makeRequest('PATCH', `reg/${clientId}`, { warp_enabled: true }, headers);

    if (!response.result?.config?.peers?.[0] || !response.result?.config?.interface) {
      throw new Error('Invalid WARP configuration response structure');
    }

    return response;
  }

  async makeRequest(method, endpoint, body = null, customHeaders = null) {
    const url = `${CloudflareWarpClient.BASE_URL}/${endpoint}`;
    const headers = customHeaders || CloudflareWarpClient.DEFAULT_HEADERS;

    const options = { method, headers };

    if (body && (method === 'POST' || method === 'PATCH')) {
      options.body = JSON.stringify(body);
    }

    try {
      const response = await fetch(url, options);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      throw new Error(`Cloudflare API request failed: ${error.message}`);
    }
  }
}

/**
 * Утилиты для криптографии
 */
class CryptoUtils {
  static generateKeyPair() {
    const keyPair = nacl.box.keyPair();
    
    return {
      privateKey: Buffer.from(keyPair.secretKey).toString('base64'),
      publicKey: Buffer.from(keyPair.publicKey).toString('base64'),
    };
  }
}

/**
 * Построитель конфигураций AWG15 (Amnezia WireGuard 1.5)
 */
class Awg15ConfigBuilder {
  // Профиль AWG15 с дефолтными параметрами
  static PROFILE = {
    jc: 120,
    jmin: 23,
    jmax: 911,
  };

  // Дефолтный endpoint
  static DEFAULT_ENDPOINT = 'engage.cloudflareclient.com:4500';

  static build(params) {
    const interfaceSection = this.buildInterfaceSection(params);
    const peerSection = this.buildPeerSection(params);
    
    return `${interfaceSection}\n\n${peerSection}`;
  }

  static buildInterfaceSection(params) {
    const { privateKey, clientIPv4, clientIPv6 } = params;
    const profile = this.PROFILE;

    // I1 значение для AWG15 (амнезия scrambling)
    const I1_VALUE = `<b 0xc10000000114367096bb0fb3f58f3a3fb8aaacd61d63a1c8a40e14f7374b8a62dccba6431716c3abf6f5afbcfb39bd008000047c32e268567c652e6f4db58bff759bc8c5aaca183b87cb4d22938fe7d8dca22a679a79e4d9ee62e4bbb3a380dd78d4e8e48f26b38a1d42d76b371a5a9a0444827a69d1ab5872a85749f65a4104e931740b4dc1e2dd77733fc7fac4f93011cd622f2bb47e85f71992e2d585f8dc765a7a12ddeb879746a267393ad023d267c4bd79f258703e27345155268bd3cc0506ebd72e2e3c6b5b0f005299cd94b67ddabe30389c4f9b5c2d512dcc298c14f14e9b7f931e1dc397926c31fbb7cebfc668349c218672501031ecce151d4cb03c4c660b6c6fe7754e75446cd7de09a8c81030c5f6fb377203f551864f3d83e27de7b86499736cbbb549b2f37f436db1cae0a4ea39930f0534aacdd1e3534bc87877e2afabe959ced261f228d6362e6fd277c88c312d966c8b9f67e4a92e757773db0b0862fb8108d1d8fa262a40a1b4171961f0704c8ba314da2482ac8ed9bd28d4b50f7432d89fd800c25a50c5e2f5c0710544fef5273401116aa0572366d8e49ad758fcb29e6a92912e644dbe227c247cb3417eabfab2db16796b2fba420de3b1dc94e8361f1f324a331ddaf1e626553138860757fd0bf687566108b77b70fb9f8f8962eca599c4a70ed373666961a8cb506b96756d9e28b94122b20f16b54f118c0e603ce0b831efea614ad836df6cf9affbdd09596412547496967da758cec9080295d853b0861670b71d9abde0d562b1a6de82782a5b0c14d297f27283a895abc889a5f6703f0e6eb95f67b2da45f150d0d8ab805612d570c2d5cb6997ac3a7756226c2f5c8982ffbd480c5004b0660a3c9468945efde90864019a2b519458724b55d766e16b0da25c0557c01f3c11ddeb024b62e303640e17fdd57dedb3aeb4a2c1b7c93059f9c1d7118d77caac1cd0f6556e46cbc991c1bb16970273dea833d01e5090d061a0c6d25af2415cd2878af97f6d0e7f1f936247b394ecb9bd484da6be936dee9b0b92dc90101a1b4295e97a9772f2263eb09431995aa173df4ca2abd687d87706f0f93eaa5e13cbe3b574fa3cfe94502ace25265778da6960d561381769c24e0cbd7aac73c16f95ae74ff7ec38124f7c722b9cb151d4b6841343f29be8f35145e1b27021056820fed77003df8554b4155716c8cf6049ef5e318481460a8ce3be7c7bfac695255be84dc491c19e9dedc449dd3471728cd2a3ee51324ccb3eef121e3e08f8e18f0006ea8957371d9f2f739f0b89e4db11e5c6430ada61572e589519fbad4498b460ce6e4407fc2d8f2dd4293a50a0cb8fcaaf35cd9a8cc097e3603fbfa08d9036f52b3e7fcce11b83ad28a4ac12dba0395a0cc871cefd1a2856fffb3f28d82ce35cf80579974778bab13d9b3578d8c75a2d196087a2cd439aff2bb33f2db24ac175fff4ed91d36a4cdbfaf3f83074f03894ea40f17034629890da3efdbb41141b38368ab532209b69f057ddc559c19bc8ae62bf3fd564c9a35d9a83d14a95834a92bae6d9a29ae5e8ece07910d16433e4c6230c9bd7d68b47de0de9843988af6dc88b5301820443bd4d0537778bf6b4c1dd067fcf14b81015f2a67c7f2a28f9cb7e0684d3cb4b1c24d9b343122a086611b489532f1c3a26779da1706c6759d96d8ab>`;

    return [
      '[Interface]',
      '# Cloudflare WARP',
      `PrivateKey = ${privateKey}`,
      `Address = ${clientIPv4}, ${clientIPv6}`,
      'DNS = 1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001',
      'MTU = 1280',
      'S1 = 0',
      'S2 = 0',
      `Jc = ${profile.jc}`,
      `Jmin = ${profile.jmin}`,
      `Jmax = ${profile.jmax}`,
      'H1 = 1',
      'H2 = 2',
      'H3 = 3',
      'H4 = 4',
      `I1 = ${I1_VALUE}`,
    ].join('\n');
  }

  static buildPeerSection(params) {
    const { publicKey, endpoint } = params;

    return [
      '[Peer]',
      `PublicKey = ${publicKey}`,
      'AllowedIPs = 0.0.0.0/0, ::/0',
      'PersistentKeepalive = 25',
      `Endpoint = ${endpoint || this.DEFAULT_ENDPOINT}`,
    ].join('\n');
  }
}

/**
 * Главный сервис для генерации AWG15 конфигураций
 */
class Awg15Service {
  constructor() {
    this.cloudflareClient = new CloudflareWarpClient();
  }

  async generateConfig(customEndpoint) {
    try {
      // Генерация ключей
      const keyPair = CryptoUtils.generateKeyPair();

      // Регистрация клиента
      const { id: clientId, token } = await this.cloudflareClient.registerClient(keyPair.publicKey);

      // Включение WARP
      const warpConfig = await this.cloudflareClient.enableWarp(clientId, token);

      // Извлечение параметров
      const peer = warpConfig.result.config.peers[0];
      const interfaceConfig = warpConfig.result.config.interface;

      // Построение конфигурации AWG15
      const config = Awg15ConfigBuilder.build({
        privateKey: keyPair.privateKey,
        publicKey: peer.public_key,
        clientIPv4: interfaceConfig.addresses.v4,
        clientIPv6: interfaceConfig.addresses.v6,
        endpoint: customEndpoint || Awg15ConfigBuilder.DEFAULT_ENDPOINT,
      });

      return {
        config,
        configName: `AWG15_${interfaceConfig.addresses.v4.split('/')[0]}.conf`,
      };
    } catch (error) {
      console.error('Failed to generate AWG15 configuration:', error);
      throw error;
    }
  }
}

// CORS заголовки
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

/**
 * Верификация токена Cloudflare Turnstile
 */
async function verifyTurnstileToken(token) {
  const secretKey = process.env.TURNSTILE_SECRET_KEY;
  
  if (!secretKey) {
    console.warn('TURNSTILE_SECRET_KEY не установлен, пропускаю проверку');
    return true;
  }
  
  if (!token) {
    return false;
  }
  
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        secret: secretKey,
        response: token,
      }),
    });
    
    const data = await response.json();
    return data.success === true;
  } catch (error) {
    console.error('Ошибка проверки Turnstile:', error);
    return false;
  }
}

// Обработчик POST запроса
export default async function handler(req, res) {
  // Обработка CORS preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method not allowed' });
  }

  try {
    const { endpoint, captchaToken } = req.body || {};
    
    // Проверка CAPTCHA
    const isHuman = await verifyTurnstileToken(captchaToken);
    if (!isHuman) {
      return res.status(403).json({
        success: false,
        message: 'Проверка не пройдена. Пожалуйста, попробуйте снова.'
      });
    }
    
    const service = new Awg15Service();
    const result = await service.generateConfig(endpoint);
    
    return res.status(200).json({
      success: true,
      config: result.config,
      configName: result.configName,
    });
  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({
      success: false,
      message: `Ошибка: ${error.message}`
    });
  }
}
