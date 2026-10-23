<#macro content>
<footer class="nusacred-provider">
<#if client?? && client.clientId == "issuer-bff-p2">
<strong>LSP Teknik Ketenagalistrikan Nusantara (demo)</strong>
<p>Credential issuer · Independent certification organization.</p>
<p>You are signing in to the certification workspace. Wallet storage and employer decisions are operated independently.</p>
<#elseif client?? && client.clientId == "company-bff-p2">
<strong>PT Karya Instalasi Nusantara (demo)</strong>
<p>Employer &amp; verifier · Independent company.</p>
<p>You are signing in to the employer workspace. Certifiers issue credentials; wallet providers store them.</p>
<#else>
<strong>PT Dompet Identitas Nusantara (demo)</strong>
<p>Independent custodial wallet provider.</p>
<p>Your certifier issues your credentials. The employer evaluates them only after you approve sharing.</p>
</#if>
<#if client?? && client.clientId == "issuer-bff-p2">
<p class="identity-service">Authentication managed independently by LSP Teknik Ketenagalistrikan Nusantara (demo).</p>
<#elseif client?? && client.clientId == "company-bff-p2">
<p class="identity-service">Authentication managed independently by PT Karya Instalasi Nusantara (demo).</p>
<#else>
<p class="identity-service">Authentication provided by PT Dompet Identitas Nusantara (demo).</p>
</#if>
<span>Synthetic demonstration</span>
</footer>
</#macro>
