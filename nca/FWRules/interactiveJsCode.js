<!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="ncegraph" content="width=device-width, initial-scale=1.0">
            <title>NCA Graph</title>
            <style>
              #selectionBox {
                width: 1400px;
                height: 300px;
                border: 0;
                margin: 0 auto;
              }
            </style>
        </head>
        <body>
            <div id="graph-container"></div>
            <pre id="selectionBox"></pre>
            <script>
                const selectableElems = document.querySelectorAll('.node');
                var selectedElems = [];
                const mainTitleText = 'Application connectivity graph'
                const doFilterExplainText = 'For filtering, Double-click on a node/edge/legend item'
                const unFilterExplainText = 'For unfiltering, Double-click on the background'
                const textSeparator = '\n---------------------------------------------------------------------------------\n\n'
                const selectSrcText = 'For connectivity explanation, Click the SOURCE node'
                const selectDstText =  'Click the DESTINATION node'
                const reselectSrcText = 'For another connectivity explanation, Click the SOURCE node'

                var filterText = mainTitleText
                var filterExplainText = doFilterExplainText
                var explainText = ''
                var explainExplainText = selectSrcText
                const selectionBox = document.getElementById('selectionBox');
                const clickableElements = document.querySelectorAll('[clickable="true"]');

                const xmlData = document.querySelector('script[type="text/xml"]').textContent;
                const parser = new DOMParser();
                const xmlDoc = parser.parseFromString(xmlData, 'text/xml');

                // find title text element
                let svg = document.querySelector('svg');

                setAllText()
                let clickFlag = false;

                function setAllText(){
                    selectionBox.innerHTML =
                        '\n<span style="color: maroon; font-size: 20px; ">'+filterText+'</span>' +'\n\n'+
                        '<span style="color: deepPink; font-size: 14px; ">'+filterExplainText+'</span>'+
                        textSeparator +
                        explainText + '\n'+
                        '<span style="color: deepPink; font-size: 14px; ">'+explainExplainText+'</span>\n'
                }

                function selectExplPeer(event) {
                  const selectedElement = event.target;
                  const parentElement = selectedElement.parentNode;
                  const polygonElement = parentElement.querySelector('polygon');
                  // find the parent node element
                  let nodeElement = parentElement;
                  while (nodeElement && !nodeElement.classList.contains('node')) {
                    nodeElement = nodeElement.parentNode;
                  }
                  clickFlag = true;
                  setTimeout(function() {
                    // If clickFlag is still true after the timer, trigger single-click action
                    if (clickFlag) {
                      if (selectedElems.length > 1) {// reset selection
                        selectedElems.forEach((item) => {
                          item.classList.remove('selected');
                          let itemParentElement = item.parentNode;
                          let itemPolygonElement = item.querySelector('polygon');
                          itemPolygonElement.setAttribute('fill', 'none');
                        });
                        selectedElems.length = 0;
                      }
                      if (nodeElement.classList.contains('selected')) {
                              // If the clicked element is already selected, deselect it
                              nodeElement.classList.remove('selected');
                              polygonElement.setAttribute('fill', 'none');
                              selectedElems.splice(selectedElems.indexOf(nodeElement), 1);
                      }
                      else if (selectedElems.length < 2) {
                        // If less than 2 elements are selected, select the clicked element
                        nodeElement.classList.add('selected');
                        if (selectedElems.length === 0) {  // src
                          polygonElement.setAttribute('fill', 'yellow');
                        }
                        else { // dst
                          polygonElement.setAttribute('fill', '#ADD8E6');
                        }
                        selectedElems.push(nodeElement);
                      }
                      // Update the selection box with the names of the selected circles
                      if (selectedElems.length == 0) {
                        explainText = ''
                        explainExplainText = selectSrcText
                      }
                      else if (selectedElems.length == 1) {
                        const src = selectedElems[0].getAttribute('title');
                        explainText = 'SOURCE node is <span style="background-color: yellow;">'+src+'</span>'
                        explainExplainText =  selectDstText;
                      }
                      else {
                        const src = selectedElems[0].getAttribute('title');
                        const dst = selectedElems[1].getAttribute('title');
                        const entry = xmlDoc.querySelector("entry[src='"+src+"'][dst='"+dst+"']");
                        if (entry) {
                          // color the src and dst names
                          let expl_text = entry.textContent;
                          let srcMatch = expl_text.match(/\(src\)([^\s]+)/);
                          let dstMatch = expl_text.match(/\(dst\)([^\s]+)/);
                          if (srcMatch) {
                            let srcText = srcMatch[1]
                            let srcReplacement = '<span style="background-color: yellow;">'+srcText+'</span>'
                            expl_text = expl_text.replace(srcText, srcReplacement);
                          }
                          if (dstMatch) {
                            dstMatch = dstMatch[1]
                            let dstReplacement = '<span style="background-color: #ADD8E6;">'+dstMatch+'</span>'
                            expl_text = expl_text.replace(dstMatch, dstReplacement);
                          }

                          explainText = expl_text;
                        }
                        else {
                          explainText = 'Did not find entry of <span style="background-color: yellow;">'+src+'</span>'+
                          ' and <span style="background-color: #ADD8E6;"> '+dst + '</span>';
                        }
                        explainExplainText = reselectSrcText
                      }
                      setAllText()
                    }
                    clickFlag = false; // Reset clickFlag
                  }, 250);
                }

                function addSelectedListeners() {
                    selectableElems.forEach(el => {
                      el.addEventListener('click', (event) => selectExplPeer(event));
                    });
                  }

                  function findSelected(element){
                  console.log(element);
                  if (element.classList.contains('selected')) {
                    return true
                  }
                  let nodes = element.querySelectorAll('.node');
                  // Iterate over nodes
                  for(let i = 0; i < nodes.length; i++) {
                    // Check if "selected" attribute is present
                    if(nodes[i].classList.contains('selected')) {
                      return true;
                    }
                  }
                  return false;
                }

                function updateTitleText(element) {
                  const clickedId = element.id;
                  filterText = jsObject[clickedId].explanation.join('\n')
                  filterExplainText = unFilterExplainText
                  setAllText()
                }

                function hideWithoutRelation(element) {
                    const clickedId = element.id;
                    const relatedIds = jsObject[clickedId].relations;
                    const highlightIds = jsObject[clickedId].highlights;
                    clickableElements.forEach(el => {
                        if (relatedIds.includes(el.id) || findSelected(el)) {
                          el.style.display = ''; // Show the element
                        }
                        if (!relatedIds.includes(el.id) && el.id !== clickedId && !findSelected(el)) {
                          el.style.display = 'none'; // Hide the element
                        }
                        if (highlightIds.includes(el.id)) {
                          el.style.strokeWidth = '2px'; // highlight the element
                        }
                        else {
                          el.style.strokeWidth = '1px'; // dont highlight the element
                        }
                    });
                }

                function showAllElements() {
                    clickableElements.forEach(el => {
                      el.style.strokeWidth = '1px'; // highlight the element
                      el.style.display = ''; // Show the element
                    });
                }

                function addDbClickListeners() {
                    // const clickableElements = document.querySelectorAll('[clickable="true"]');
                    clickableElements.forEach(el => {
                      if (el.classList.contains('background')) { // Check if the event target is the SVG background
                        el.addEventListener('dblclick', function() {
                          showAllElements();
                          clearSelection(); // dbclick sellects the text it was clicked on, its annoying...
                          filterText = mainTitleText
                          filterExplainText = doFilterExplainText
                          setAllText()
                        });
                      }
                      else {
                        el.addEventListener('dblclick', function() {
                            clickFlag = false
                            hideWithoutRelation(el);
                            updateTitleText(el)
                            clearSelection();
                          });
                      }
                    });
                }

                function clearSelection() {
                  if (window.getSelection) {
                    window.getSelection().removeAllRanges(); // For most modern browsers
                  } else if (document.selection && document.selection.empty) {
                    document.selection.empty(); // For older IE versions (<= IE 9)
                  }
                }

                document.addEventListener('DOMContentLoaded', function() {
                    addDbClickListeners();
                    addSelectedListeners();
                });

            </script>
        </body>
    </html>
