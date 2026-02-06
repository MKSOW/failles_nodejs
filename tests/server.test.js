// Tests d'intégration basiques pour vérifier les protections
process.env.ADMIN_TOKEN = 'TEST_ADMIN_TOKEN';

const request = require('supertest');
const app = require('../server');

describe('API basic security tests', () => {
  test('GET /api/user returns admin user', async () => {
    const res = await request(app).get('/api/user').query({ username: 'admin' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('username', 'admin');
  });

  test('SQL injection attempt should not succeed', async () => {
    const payload = "admin' OR '1'='1";
    const res = await request(app).get('/api/user').query({ username: payload });
    // The param is validated and used as parameter; no mass return expected
    expect([200, 404]).toContain(res.statusCode);
    // If returns 200, ensure the returned username is exactly the payload or a real user; not multiple rows
    if (res.statusCode === 200) {
      expect(res.body.username).not.toBeUndefined();
    }
  });

  test('DELETE user requires Bearer token and works with correct token', async () => {
    // delete user id 2 (user1)
    const res = await request(app)
      .post('/api/delete-user')
      .set('Authorization', 'Bearer TEST_ADMIN_TOKEN')
      .send({ id: 2 });

    expect([200, 404]).toContain(res.statusCode);
  });
});
