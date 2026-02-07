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
  static DEFAULT_ENDPOINT = '162.159.195.1:500';

  static build(params) {
    const interfaceSection = this.buildInterfaceSection(params);
    const peerSection = this.buildPeerSection(params);
    
    return `${interfaceSection}\n\n${peerSection}`;
  }

  static buildInterfaceSection(params) {
    const { privateKey, clientIPv4, clientIPv6 } = params;
    const profile = this.PROFILE;

    // I1 значение для AWG15 (амнезия scrambling)
    const I1_VALUE = `<b 0xc2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420a91a8c427e87d6cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55c59bec101634db90afb83f75b19fe703179e26a31902324c73f82d9354e1ed8da39af610afcb27e6590a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0ee6332e19bdf48ffc387a97227aa97b205a485d282cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae1c493482128bc0830c9e1233f0027a0d262f92b49d9d8abd9a9e0341f6e1214761043c021d7aa8c464b9d865f5fbe234e49626e00712031703a3e23ef82975f014ee1e1dc428521dc23ce7c6c13663b19906240b3efe403cf30559d798871557e4e60e86c29ea4504ed4d9bb8b549d0e8acd6c334c39bb8fb42ede68fb2aadf00cfc8bcc12df03602bbd4fe701d64a39f7ced112951a83b1dbbe6cd696dd3f15985c1b9fef72fa8d0319708b633cc4681910843ce753fac596ed9945d8b839aeff8d3bf0449197bd0bb22ab8efd5d63eb4a95db8d3ffc796ed5bcf2f4a136a8a36c7a0c65270d511aebac733e61d414050088a1c3d868fb52bc7e57d3d9fd132d78b740a6ecdc6c24936e92c28672dbe00928d89b891865f885aeb4c4996d50c2bbbb7a99ab5de02ac89b3308e57bcecf13f2da0333d1420e18b66b4c23d625d836b538fc0c221d6bd7f566a31fa292b85be96041d8e0bfe655d5dc1afed23eb8f2b3446561bbee7644325cc98d31cea38b865bdcc507e48c6ebdc7553be7bd6ab963d5a14615c4b81da7081c127c791224853e2d19bafdc0d9f3f3a6de898d14abb0e2bc849917e0a599ed4a541268ad0e60ea4d147dc33d17fa82f22aa505ccb53803a31d10a7ca2fea0b290a52ee92c7bf4aab7cea4e3c07b1989364eed87a3c6ba65188cd349d37ce4eefde9ec43bab4b4dc79e03469c2ad6b902e28e0bbbbf696781ad4edf424ffb35ce0236d373629008f142d04b5e08a124237e03e3149f4cdde92d7fae581a1ac332e26b2c9c1a6bdec5b3a9c7a2a870f7a0c25fc6ce245e029b686e346c6d862ad8df6d9b62474fbc31dbb914711f78074d4441f4e6e9edca3c52315a5c0653856e23f681558d669f4a4e6915bcf42b56ce36cb7dd3983b0b1d6fdf0f8efddb68e7ca0ae9dd4570fe6978fbb524109f6ec957ca61f1767ef74eb803b0f16abd0087cf2d01bc1db1c01d97ac81b3196c934586963fe7cf2d310e0739621e8bd00dc23fded18576d8c8f285d7bb5f43b547af3c76235de8b6f757f817683b2151600b11721219212bf27558edd439e73fce951f61d582320e5f4d6c315c71129b719277fc144bbe8ded25ab6d29b6`;

    return [
      '[Interface]',
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

  async generateConfig() {
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
        endpoint: Awg15ConfigBuilder.DEFAULT_ENDPOINT,
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
    const service = new Awg15Service();
    const result = await service.generateConfig();
    
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
