```dataviewjs

// ════════════════════════════════════════════════════════════════════════════
// SEÇÃO 1: LINKS RÁPIDOS PARA OS ALVOS
// ════════════════════════════════════════════════════════════════════════════

const folder = dv.current().file.folder;
const pages = dv.pages(`"${folder}"`);
const tasksByTarget = {};

// Coleta tarefas por alvo
for (const page of pages) {
    if (page.file.name === "Tarefas") continue;
    
    if (page.file.tasks && page.file.tasks.length > 0) {
        const pendingTasks = page.file.tasks.filter(t => !t.completed);
        
        if (pendingTasks.length > 0) {
            const targetName = page.file.folder.split('/').pop() || page.file.name;
            
            if (!tasksByTarget[targetName]) {
                tasksByTarget[targetName] = {
                    tasks: [],
                    filePath: page.file.path,
                    fileName: page.file.name
                };
            }
            
            tasksByTarget[targetName].tasks.push(...pendingTasks);
        }
    }
}

const targetNames = Object.keys(tasksByTarget);


// Renderiza a seção de links rápidos
if (targetNames.length > 0) {
    dv.header(2, "🔗 Acesso Rápido aos Alvos");
    
    let linksHtml = '<div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px;">';
    
    for (const targetName of targetNames.sort()) {
        linksHtml += `<a href="${tasksByTarget[targetName].filePath}" class="internal-link" style="background-color: #3b82f6; color: white; padding: 6px 12px; border-radius: 6px; font-size: 0.9em; text-decoration: none; display: inline-block;">${targetName}</a>`;
    }
    
    linksHtml += '</div>';
    dv.paragraph(linksHtml);
    dv.paragraph("---");
}

// ════════════════════════════════════════════════════════════════════════════
// SEÇÃO 2: TAREFAS PENDENTES - VERSÃO "CAPTURE & MOVE"
// Renderiza headers HTML + permite Dataview renderizar naturalmente + move para containers
// ════════════════════════════════════════════════════════════════════════════

if (targetNames.length === 0) {
    dv.header(2, "✅ Nenhuma tarefa pendente");
    dv.paragraph("_Parabéns! Todas as tarefas foram concluídas._");
} else {
    dv.header(2, "📋 Tarefas Pendentes");
    
    const totalTasks = targetNames.reduce((sum, target) => sum + tasksByTarget[target].tasks.length, 0);
    dv.paragraph(`**${targetNames.length}** alvos | **${totalTasks}** tarefas pendentes`);
    dv.paragraph("---");
    
    // Função para determinar cor e ícone baseado na quantidade de tarefas
    const getStatusStyle = (count) => {
        if (count <= 4) return { color: '#10b981', icon: '🟢', label: 'Baixa' };
        if (count <= 10) return { color: '#f59e0b', icon: '🟡', label: 'Média' };
        return { color: '#ef4444', icon: '🔴', label: 'Alta' };
    };
    
    let targetIndex = 0;
    const taskListElements = []; // Guarda as task lists renderizadas
    
    for (const targetName of targetNames.sort()) {
        const targetData = tasksByTarget[targetName];
        const taskCount = targetData.tasks.length;
        const style = getStatusStyle(taskCount);
        const uniqueId = `target-tasks-${targetIndex}`;
        
        // Cria header com fold
        const headerDiv = document.createElement('div');
        headerDiv.className = 'task-target-header';
        headerDiv.dataset.targetId = uniqueId;
        headerDiv.style.cssText = `margin-bottom: 8px; padding: 8px 12px; border-left: 4px solid ${style.color}; border-radius: 4px; background-color: rgba(59, 130, 246, 0.03); cursor: pointer; user-select: none;`;
        
        const arrow = document.createElement('span');
        arrow.id = `${uniqueId}-arrow`;
        arrow.textContent = '▶';
        arrow.style.cssText = 'display: inline-block; transition: transform 0.2s; margin-right: 4px;';
        
        headerDiv.innerHTML = `
            <span style="font-weight: 600; font-size: 1em; color: ${style.color};">
                ${style.icon} ${targetName}
            </span>
            <span style="background-color: ${style.color}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; margin-left: 8px;">${taskCount}</span>
            <span style="color: #9ca3af; font-size: 0.8em; margin-left: 6px;">${style.label}</span>
            <span style="float: right; font-size: 0.85em; color: #6b7280;">
                📄 <a href="${targetData.filePath}" class="internal-link">${targetData.fileName}</a>
            </span>
        `;
        
        headerDiv.insertBefore(arrow, headerDiv.firstChild);
        dv.container.appendChild(headerDiv);
        
        // Container vazio que vai receber as tarefas depois
        const taskWrapper = document.createElement('div');
        taskWrapper.id = uniqueId;
        taskWrapper.className = 'task-wrapper-collapsible';
        taskWrapper.style.cssText = 'display: none; margin-left: 20px; margin-bottom: 16px; padding-left: 12px; border-left: 2px solid #e5e7eb;';
        dv.container.appendChild(taskWrapper);
        
        // Marca onde as tarefas serão inseridas
        const placeholder = document.createElement('div');
        placeholder.id = `placeholder-${targetIndex}`;
        placeholder.className = 'task-placeholder';
        dv.container.appendChild(placeholder);
        
        // Renderiza as tarefas NATURALMENTE (Dataview vai colocar depois do placeholder)
        dv.taskList(targetData.tasks, false);
        
        taskListElements.push({ id: uniqueId, index: targetIndex });
        targetIndex++;
    }
    
    dv.paragraph("---");
    
    // ════════════════════════════════════════════════════════════════════════
    // SEÇÃO 3: "CAPTURE & MOVE" - Move as task lists para dentro dos wrappers
    // ════════════════════════════════════════════════════════════════════════
    
    setTimeout(() => {
        taskListElements.forEach((item, idx) => {
            const wrapper = document.getElementById(item.id);
            const placeholder = document.getElementById(`placeholder-${item.index}`);
            
            if (!wrapper || !placeholder) return;
            
            // Pega o próximo elemento após o placeholder
            let taskListElement = placeholder.nextElementSibling;
            
            // O Dataview envolve a UL em uma DIV, então precisamos pegar essa DIV inteira
            // OU pegar a UL dentro dela
            if (taskListElement) {
                // Se for uma DIV que contém UL, pega a DIV inteira
                const ul = taskListElement.querySelector('ul.contains-task-list');
                if (ul) {
                    // Move a DIV inteira (que contém a UL) para dentro do wrapper
                    wrapper.appendChild(taskListElement);
                } else if (taskListElement.tagName === 'UL' && taskListElement.classList.contains('contains-task-list')) {
                    // Se for a UL diretamente, move ela
                    wrapper.appendChild(taskListElement);
                }
                
                // Remove o placeholder
                placeholder.remove();
            }
        });
        
        // Adiciona event listeners para toggle
        dv.container.addEventListener('click', function(e) {
            const header = e.target.closest('.task-target-header');
            if (!header) return;
            if (e.target.tagName === 'A' || e.target.closest('a')) return;
            
            const targetId = header.dataset.targetId;
            const taskList = document.getElementById(targetId);
            const arrow = document.getElementById(`${targetId}-arrow`);
            
            if (taskList && arrow) {
                const isHidden = taskList.style.display === 'none';
                taskList.style.display = isHidden ? 'block' : 'none';
                arrow.style.transform = isHidden ? 'rotate(90deg)' : 'rotate(0deg)';
            }
        });
    }, 300);
}

// ════════════════════════════════════════════════════════════════════════════
// SEÇÃO 4: AUTO-ADD COMPLETION DATE
// Monitora mudanças nas tarefas e adiciona data de conclusão
// ════════════════════════════════════════════════════════════════════════════

const observer = new MutationObserver(async (mutations) => {
    for (const mutation of mutations) {
        if (mutation.type === 'attributes' || mutation.type === 'childList') {
            const checkboxes = dv.container.querySelectorAll('input[type="checkbox"][data-task]:checked');
            
            for (const checkbox of checkboxes) {
                const taskItem = checkbox.closest('.task-list-item');
                if (taskItem && !taskItem.dataset.dateAdded) {
                    taskItem.dataset.dateAdded = 'true';
                    await addCompletionDate(taskItem);
                }
            }
        }
    }
});

observer.observe(dv.container, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['data-task', 'checked']
});

async function addCompletionDate(taskElement) {
    try {
        await new Promise(resolve => setTimeout(resolve, 100));
        
        const taskTextElement = taskElement.querySelector('.task-list-item-checkbox')?.nextSibling;
        if (!taskTextElement) return;
        
        const taskText = taskTextElement.textContent?.trim();
        if (!taskText) return;
        if (taskText.includes('✅') || taskText.includes('Concluída em:')) return;
        
        const today = new Date().toISOString().split('T')[0];
        const completionMark = ` ✅ Concluída em: ${today}`;
        
        for (const targetName of targetNames) {
            const targetData = tasksByTarget[targetName];
            const file = app.vault.getAbstractFileByPath(targetData.filePath);
            
            if (file) {
                let content = await app.vault.read(file);
                const lines = content.split('\n');
                let modified = false;
                
                for (let i = 0; i < lines.length; i++) {
                    if (lines[i].includes('- [ ]') && lines[i].includes(taskText.substring(0, 30))) {
                        lines[i] = lines[i].replace('- [ ]', '- [x]') + completionMark;
                        modified = true;
                        break;
                    }
                }
                
                if (modified) {
                    await app.vault.modify(file, lines.join('\n'));
                    console.log(`✅ Data de conclusão adicionada: ${taskText}`);
                    new Notice(`✅ Tarefa concluída em ${today}`);
                    break;
                }
            }
        }
    } catch (error) {
        console.error('Erro ao adicionar data de conclusão:', error);
    }
}
```
