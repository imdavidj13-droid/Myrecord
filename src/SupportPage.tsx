/**
 * Age-inclusive, static support signposting. No forms, messages, analytics,
 * accounts, location lookup or crisis-triage claims.
 *
 * Source checks (2026-11-14):
 * https://www.nhs.uk/nhs-services/mental-health-services/where-to-get-urgent-help-for-mental-health/
 * https://www.childline.org.uk/about/about-childline/
 * https://www.samaritans.org/
 */
import {ArrowUpRight,Heart,ShieldAlert,Phone,EyeOff} from "lucide-react";

export default function SupportPage({onExit}:{onExit:()=>void}){
  return <section className="support-page" aria-label="Help and safety">
    <div className="support-page-intro">
      <span className="eyebrow"><Heart size={15}/> SUPPORT AND SAFETY</span>
      <h1>Support is available.<br/><em>You don't have to explain anything here.</em></h1>
      <p>MySafeSpace is a writing website in development, not a monitored helpline or emergency service. You can leave at any time, and you never need to share your experience with us to find support.</p>
      <button type="button" className="button button-outline" onClick={onExit}><EyeOff size={16}/> Quick exit</button>
    </div>
    <div className="support-page-grid">
      <article className="support-resource">
        <span className="support-resource-label"><ShieldAlert size={17}/> Immediate danger</span>
        <h2>Get urgent help</h2>
        <p>If you or somebody else is in immediate danger, contact your local emergency services. In the UK, call <strong>999</strong>. For urgent mental health advice in England, NHS 111 can help.</p>
        <a href="https://www.nhs.uk/nhs-services/mental-health-services/where-to-get-urgent-help-for-mental-health/" target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">NHS urgent help information <ArrowUpRight size={16}/></a>
      </article>
      <article className="support-resource">
        <span className="support-resource-label"><Heart size={17}/> Children and young people</span>
        <h2>Childline</h2>
        <p>For anyone under 19 in the UK, Childline offers confidential support. Call <strong>0800 1111</strong> or visit its website to find ways to talk.</p>
        <a href="https://www.childline.org.uk/get-support/" target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">Visit Childline <ArrowUpRight size={16}/></a>
      </article>
      <article className="support-resource">
        <span className="support-resource-label"><Phone size={17}/> Someone to talk to</span>
        <h2>Samaritans</h2>
        <p>In the UK and Ireland, Samaritans offers a listening service at any time. Call free on <strong>116 123</strong>.</p>
        <a href="https://www.samaritans.org/" target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">Visit Samaritans <ArrowUpRight size={16}/></a>
      </article>
    </div>
    <p className="support-page-note">The contacts above are UK-focused. If you live elsewhere, use local emergency services or recognised support organisations in your country. External sites have their own privacy policies and may appear in browser history.</p>
  </section>;
}
