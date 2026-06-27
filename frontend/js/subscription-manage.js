async function openSubscriptionModal() {
  const token = localStorage.getItem('dovtek_token');
  if (!token) return;
  
  let modalEl = document.getElementById('subscription-manage-modal');
  if (!modalEl) {
    modalEl = document.createElement('div');
    modalEl.id = 'subscription-manage-modal';
    modalEl.style.cssText = `
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      display: flex; justify-content: center; align-items: center;
      z-index: 10000;
      font-family: var(--font-sans, sans-serif);
      opacity: 0; transition: opacity 0.3s ease;
    `;
    document.body.appendChild(modalEl);
  }
  
  modalEl.innerHTML = `
    <div style="background: var(--card, #1e293b); border: 1px solid var(--border, #334155); border-radius: var(--radius-md, 12px); padding: 32px; width: 90%; max-width: 450px; text-align: center; color: var(--white, #fff); box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
      <div class="spinner" style="border: 3px solid rgba(255,255,255,0.1); border-top: 3px solid var(--teal, #0d9488); border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 16px;"></div>
      <p style="margin: 0; font-size: 14px; color: var(--muted, #94a3b8);">Loading subscription details...</p>
    </div>
  `;
  setTimeout(() => modalEl.style.opacity = '1', 50);

  if (!document.getElementById('spin-anim-style')) {
    const style = document.createElement('style');
    style.id = 'spin-anim-style';
    style.innerHTML = '@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }';
    document.head.appendChild(style);
  }
  
  let user;
  try {
    const r = await fetch((window.API || window.location.origin) + '/auth/me', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (!r.ok) throw new Error();
    user = await r.json();
    localStorage.setItem('dovtek_user', JSON.stringify(user));
  } catch (e) {
    modalEl.innerHTML = `
      <div style="background: var(--card, #1e293b); border: 1px solid var(--border, #334155); border-radius: var(--radius-md, 12px); padding: 32px; width: 90%; max-width: 450px; text-align: center; color: var(--white, #fff);">
        <p style="color: #ef4444; margin-bottom: 20px;">Failed to load subscription details. Please log in again.</p>
        <button onclick="document.getElementById('subscription-manage-modal').remove()" style="padding: 8px 16px; background: var(--teal, #0d9488); border: none; border-radius: 6px; color: #000; cursor: pointer;">Close</button>
      </div>
    `;
    return;
  }

  const plan = user.plan;
  const pendingPlan = user.pending_plan;
  const endsAt = user.subscription_ends_at;
  
  let contentHtml = '';
  const formattedDate = endsAt ? new Date(endsAt).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }) : 'next renewal date';
  
  if (plan === 'free') {
    contentHtml = `
      <h3 style="margin-top: 0; margin-bottom: 12px; font-size: 20px; font-weight: 800;">Free Plan</h3>
      <p style="font-size: 14px; line-height: 1.6; color: var(--muted, #94a3b8); margin-bottom: 24px;">
        You are currently on the Free Plan. Upgrade to access features like Chrome Extension background protection and unlimited scans!
      </p>
      <div style="display: flex; gap: 12px; justify-content: flex-end;">
        <button onclick="document.getElementById('subscription-manage-modal').remove()" style="padding: 10px 18px; background: transparent; border: 1px solid var(--border, #334155); border-radius: 6px; color: var(--white, #fff); cursor: pointer; font-size: 13px;">Close</button>
        <a href="/plans" style="padding: 10px 18px; background: var(--teal, #0d9488); border: none; border-radius: 6px; color: #000; text-decoration: none; font-weight: 700; font-size: 13px; display: inline-block;">🚀 View Upgrade Plans</a>
      </div>
    `;
  } else if (pendingPlan) {
    const actionText = pendingPlan === 'free' ? 'Cancellation' : 'Downgrade to ShieldIQ Pro';
    contentHtml = `
      <h3 style="margin-top: 0; margin-bottom: 12px; font-size: 20px; font-weight: 800; color: #ff9f43;">⚠️ Pending Plan Change</h3>
      <p style="font-size: 14px; line-height: 1.6; color: var(--white, #fff); margin-bottom: 16px;">
        You have requested a <strong>${actionText}</strong>.
      </p>
      <div style="background: rgba(255, 159, 67, 0.1); border-left: 4px solid #ff9f43; padding: 12px; border-radius: 4px; margin-bottom: 24px; text-align: left;">
        <p style="margin: 0; font-size: 13px; line-height: 1.5; color: #ff9f43;">
          Your current <strong>Shield ${plan === 'plus' ? 'Plus' : 'Pro'}</strong> plan remains fully active until <strong>${formattedDate}</strong>. After this date, your plan will switch to <strong>${pendingPlan.toUpperCase()}</strong> and you will no longer be charged.
        </p>
      </div>
      <div style="display: flex; gap: 12px; justify-content: flex-end; align-items: center; flex-wrap: wrap;">
        <button onclick="document.getElementById('subscription-manage-modal').remove()" style="padding: 10px 18px; background: transparent; border: 1px solid var(--border, #334155); border-radius: 6px; color: var(--white, #fff); cursor: pointer; font-size: 13px;">Close</button>
        <button id="resumeSubBtn" onclick="resumeSubscription()" style="padding: 10px 18px; background: var(--teal, #0d9488); border: none; border-radius: 6px; color: #000; font-weight: 700; cursor: pointer; font-size: 13px; display: flex; align-items: center; gap: 6px;">
          Keep Current Subscription
        </button>
      </div>
    `;
  } else {
    const isPlus = plan === 'plus';
    let optionsHtml = '';
    
    if (isPlus) {
      optionsHtml = `
        <div style="margin-bottom: 20px; text-align: left;">
          <label style="display: block; margin-bottom: 12px; font-size: 14px; font-weight: 700; color: var(--white, #fff);">Select New Plan:</label>
          <div style="display: flex; flex-direction: column; gap: 12px;">
            <label style="display: flex; align-items: flex-start; gap: 12px; background: rgba(255,255,255,0.03); border: 1px solid var(--border, #334155); padding: 12px; border-radius: 8px; cursor: pointer;" onclick="document.getElementById('plan-pro').checked=true">
              <input type="radio" id="plan-pro" name="downgradePlan" value="pro" checked style="margin-top: 3px;">
              <div style="margin-left: 8px;">
                <strong style="color: var(--white, #fff); font-size: 13px; display: block;">Downgrade to ShieldIQ Pro</strong>
                <span style="display: block; font-size: 12px; color: var(--muted, #94a3b8); margin-top: 4px;">Unlimited scans. No Chrome Extension access. Only takes effect on ${formattedDate}.</span>
              </div>
            </label>
            <label style="display: flex; align-items: flex-start; gap: 12px; background: rgba(255,255,255,0.03); border: 1px solid var(--border, #334155); padding: 12px; border-radius: 8px; cursor: pointer;" onclick="document.getElementById('plan-free').checked=true">
              <input type="radio" id="plan-free" name="downgradePlan" value="free" style="margin-top: 3px;">
              <div style="margin-left: 8px;">
                <strong style="color: #ef4444; font-size: 13px; display: block;">Cancel Subscription (Downgrade to Free)</strong>
                <span style="display: block; font-size: 12px; color: var(--muted, #94a3b8); margin-top: 4px;">Downgrade to 3 scans/day. Only takes effect on ${formattedDate}.</span>
              </div>
            </label>
          </div>
        </div>
      `;
    } else {
      optionsHtml = `
        <div style="margin-bottom: 24px; text-align: left;">
          <p style="font-size: 14px; line-height: 1.5; color: var(--muted, #94a3b8); margin-bottom: 16px;">
            Canceling your subscription will downgrade your account to the Free Plan at the end of the billing period.
          </p>
          <div style="background: rgba(239, 68, 68, 0.08); border-left: 4px solid #ef4444; padding: 12px; border-radius: 4px; text-align: left;">
            <p style="margin: 0; font-size: 13px; line-height: 1.5; color: #ef4444;">
              Your current <strong>ShieldIQ Pro</strong> plan features will remain active until <strong>${formattedDate}</strong>.
            </p>
          </div>
          <input type="hidden" id="plan-free" name="downgradePlan" value="free">
        </div>
      `;
    }
    
    contentHtml = `
      <h3 style="margin-top: 0; margin-bottom: 8px; font-size: 20px; font-weight: 800; color: var(--teal, #0d9488);">🛡️ Manage Subscription</h3>
      <p style="font-size: 13px; color: var(--muted, #94a3b8); margin-bottom: 20px;">
        Active Plan: <span style="color: var(--white, #fff); font-weight: 700;">Shield ${isPlus ? 'Plus' : 'Pro'}</span>
      </p>
      
      ${optionsHtml}
      
      <div style="display: flex; gap: 12px; justify-content: flex-end; flex-wrap: wrap; margin-top: 20px;">
        <button onclick="document.getElementById('subscription-manage-modal').remove()" style="padding: 10px 18px; background: transparent; border: 1px solid var(--border, #334155); border-radius: 6px; color: var(--white, #fff); cursor: pointer; font-size: 13px;">Keep Plan</button>
        <button id="confirmChangeBtn" onclick="confirmSubscriptionChange()" style="padding: 10px 18px; background: #ef4444; border: none; border-radius: 6px; color: var(--white, #fff); font-weight: 700; cursor: pointer; font-size: 13px; display: flex; align-items: center; gap: 6px;">
          Confirm Change
        </button>
      </div>
    `;
  }
  
  modalEl.innerHTML = `
    <div style="background: var(--card, #1e293b); border: 1px solid var(--border, #334155); border-radius: var(--radius-md, 12px); padding: 32px; width: 90%; max-width: 480px; text-align: center; color: var(--white, #fff); box-shadow: 0 10px 25px rgba(0,0,0,0.5); position: relative;">
      <button onclick="document.getElementById('subscription-manage-modal').remove()" style="position: absolute; top: 16px; right: 16px; background: transparent; border: none; color: var(--muted, #94a3b8); font-size: 20px; cursor: pointer; line-height: 1;">&times;</button>
      <div id="subscription-modal-body">${contentHtml}</div>
    </div>
  `;
}

async function confirmSubscriptionChange() {
  const token = localStorage.getItem('dovtek_token');
  const btn = document.getElementById('confirmChangeBtn');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner" style="border: 2px solid rgba(255,255,255,0.1); border-top: 2px solid white; border-radius: 50%; width: 14px; height: 14px; animation: spin 1s linear infinite;"></div> Saving...';
  }
  
  let targetPlan = 'free';
  const proRadio = document.getElementById('plan-pro');
  if (proRadio && proRadio.checked) {
    targetPlan = 'pro';
  }
  
  try {
    const endpoint = targetPlan === 'free' ? '/api/billing/cancel' : '/api/billing/change-subscription';
    const body = targetPlan === 'free' ? undefined : JSON.stringify({ target_plan: targetPlan });
    const method = 'POST';
    
    const apiBase = window.API || window.location.origin;
    const r = await fetch(apiBase + endpoint, {
      method: method,
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: body
    });
    
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail?.message || data.detail || 'Failed to update subscription');
    
    alert(data.message || 'Subscription change updated successfully!');
    document.getElementById('subscription-manage-modal').remove();
    
    // Update local storage user object
    const userStr = localStorage.getItem('dovtek_user');
    if (userStr) {
      const u = JSON.parse(userStr);
      u.pending_plan = targetPlan;
      localStorage.setItem('dovtek_user', JSON.stringify(u));
    }
    
    location.reload();
  } catch (e) {
    alert(e.message || 'Failed to update subscription. Please try again.');
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Confirm Change';
    }
  }
}

async function resumeSubscription() {
  const token = localStorage.getItem('dovtek_token');
  const btn = document.getElementById('resumeSubBtn');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner" style="border: 2px solid rgba(255,255,255,0.1); border-top: 2px solid white; border-radius: 50%; width: 14px; height: 14px; animation: spin 1s linear infinite;"></div> Resuming...';
  }
  
  try {
    const apiBase = window.API || window.location.origin;
    const r = await fetch(apiBase + '/api/billing/resume-subscription', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    });
    
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail?.message || data.detail || 'Failed to resume subscription');
    
    alert(data.message || 'Subscription resumed successfully!');
    document.getElementById('subscription-manage-modal').remove();
    
    // Update local storage user object
    const userStr = localStorage.getItem('dovtek_user');
    if (userStr) {
      const u = JSON.parse(userStr);
      u.pending_plan = null;
      localStorage.setItem('dovtek_user', JSON.stringify(u));
    }
    
    location.reload();
  } catch (e) {
    alert(e.message || 'Failed to resume subscription. Please try again.');
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Keep Current Subscription';
    }
  }
}
