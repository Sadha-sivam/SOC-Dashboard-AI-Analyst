import { WazuhService } from './services/WazuhService';
import dotenv from 'dotenv';
dotenv.config();

async function testWazuh() {
  const wazuh = new WazuhService();
  console.log(`Testing Wazuh API Connection to ${process.env.WAZUH_URL}...`);
  try {
    await wazuh.authenticate();
    console.log("✅ Authenticated successfully!");
    const agents = await wazuh.getAgents();
    console.log(`✅ Retrieved ${agents.length} agents:`);
    agents.forEach((a: any) => console.log(`  - ${a.name} (${a.ip}) [${a.status}]`));
  } catch (error: any) {
    console.error("❌ Connection Failed. Check your credentials in backend/.env!");
  }
}

testWazuh();
