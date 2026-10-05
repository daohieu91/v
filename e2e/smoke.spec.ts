import { expect, test } from '@playwright/test';
test('scaffold page renders and shows the attestation copy date', async ({ page }) => {
  await page.goto('');
  await expect(page.locator('#app')).toHaveText('CameraStamp');
  await expect(page.locator('#attested')).toHaveText(/copied on \d{4}-\d{2}-\d{2}/);
});
