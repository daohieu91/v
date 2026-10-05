import { expect, test } from '@playwright/test';
test('scaffold page renders', async ({ page }) => {
  await page.goto('');
  await expect(page.locator('#app')).toHaveText('CameraStamp');
});
