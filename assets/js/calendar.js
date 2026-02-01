document.addEventListener("DOMContentLoaded", function () {
    const el = document.getElementById("calendar");
    const modal = document.getElementById("ctfModal");
    const closeBtn = document.getElementsByClassName("close")[0];
  
    if (!el || !window.ctfEvents) return;
    
    closeBtn.onclick = function() {
        modal.style.display = "none";
    }
    
    window.onclick = function(event) {
        if (event.target == modal) {
        modal.style.display = "none";
        }
    }
    
    const calendar = new FullCalendar.Calendar(el, {
        initialView: "dayGridMonth",
        height: "auto",
        hour: 'numeric',
        events: window.ctfEvents,
        eventTimeFormat: {
            hour: '2-digit',
            meridiem: 'short'
        },
        timeZone: 'local', 
        eventClick: function(info) {
        info.jsEvent.preventDefault();
        
        const event = info.event;
        const props = event.extendedProps;
        
        document.getElementById("modalTitle").textContent = event.title;
        
        const startStr = event.start.toLocaleString('en-US', { 
            dateStyle: 'medium', 
            timeStyle: 'short' 
        });
        const endStr = event.end ? event.end.toLocaleString('en-US', { 
            dateStyle: 'medium', 
            timeStyle: 'short' 
        }) : 'N/A';
        
        let bodyHTML = `
            <p><strong>Start:</strong> ${startStr}</p>
            <p><strong>End:</strong> ${endStr}</p>
        `;
        
        if (props.location) {
            bodyHTML += `<p><strong>Location:</strong> ${props.location}</p>`;
        }
        if (props.description) {
            bodyHTML += `<p><strong>Description:</strong> ${props.description}</p>`;
        }
        if (props.weight) {
            bodyHTML += `<p><strong>Weight:</strong> ${props.weight}</p>`;
        }
        if (props.format) {
            bodyHTML += `<p><strong>Format:</strong> ${props.format}</p>`;
        }
        if (props.open) {
        bodyHTML += `<p><strong>Participation:</strong> Open to all</p>`;
        } else if (props.ccit) {
        bodyHTML += `<p><strong>Participation:</strong> CCIT members only</p>`;
        } else {
        bodyHTML += `<p><strong>Participation:</strong> MadrHacks team members only</p>`;
        }
        
        document.getElementById("modalBody").innerHTML = bodyHTML;
        document.getElementById("modalLink").href = event.url;
        
        modal.style.display = "block";
        }
    });
    
    calendar.render();
});