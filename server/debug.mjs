import { MongoMemoryServer } from 'mongodb-memory-server';
import request from 'supertest';

const m = await MongoMemoryServer.create();
process.env.MONGODB_URI = m.getUri('t');
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'x'.repeat(40);
process.env.OTP_TEST_CODE = '424242';

const { connect } = await import('./src/db.js');
await connect(process.env.MONGODB_URI, { quiet: true });
const { createApp } = await import('./src/app.js');
const app = createApp();
const api = () => request(app);

const sent = await api().post('/api/auth/send-otp').send({ phone: '+10000000888' });
console.log('SEND', sent.status, JSON.stringify(sent.body));

const ver = await api()
  .post('/api/auth/verify-otp')
  .send({ phone: '+10000000888', code: '424242' });
console.log('VERIFY', ver.status, JSON.stringify(ver.body).slice(0, 700));

await m.stop();
process.exit(0);
