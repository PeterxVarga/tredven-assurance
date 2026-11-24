'use strict';
const input=document.getElementById('search'), count=document.getElementById('count');
if(input && count){
 const cards=Array.from(document.querySelectorAll('[data-case]'));
 input.addEventListener('input',()=>{
  const terms=input.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  let visible=0;
  for(const card of cards){
   card.hidden=!terms.every(term=>card.textContent.toLowerCase().includes(term));
   if(!card.hidden)visible++;
  }
  count.textContent=visible+' results';
 });
}
