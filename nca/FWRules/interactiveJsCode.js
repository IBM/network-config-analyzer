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
                border: 1px solid black;
                margin: 10px;
                padding: 5px;
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
                const filterExplainText = 'For filtering, Please double-click on a node'
                const unfilterExplainText = 'For unfiltering, Please double-click on the background'
                const textSeparator = '\n---------------------------------------------------------------------------------\n\n'
                const selectSrcText = 'For connectivity explanation, Please select the SOURCE node'
                const selectDstText = 'For connectivity explanation, Please select the DESTINATION node'
                const reselectSrcText = 'For another connectivity explanation, Please select the SOURCE node'

                var filterText = mainTitleText + '\n' + filterExplainText
                var explainText = selectSrcText
                const selectionBox = document.getElementById('selectionBox');
                const clickableElements = document.querySelectorAll('[clickable="true"]');

                const xmlData = document.querySelector('script[type="text/xml"]').textContent;
                const parser = new DOMParser();
                const xmlDoc = parser.parseFromString(xmlData, 'text/xml');

                // find title text element
                let svg = document.querySelector('svg');
                // Find the element with id="index"
                let indexElement = svg.querySelector('#index');
                // Find the text element inside the "index" element
                let titleTextElements = indexElement.querySelectorAll('text');

                selectionBox.innerHTML = filterText + textSeparator + explainText
                let clickFlag = false;

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
                        explainText = selectSrcText;
                      }
                      else if (selectedElems.length == 1) {
                        const src = selectedElems[0].getAttribute('title');
                        explainText = selectDstText;
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
                            let srcReplacement = '<span style="background-color: yellow;">'+srcText+'</span>';
                            expl_text = expl_text.replace(srcText, srcReplacement);
                          }
                          if (dstMatch) {
                            dstMatch = dstMatch[1]
                            let dstReplacement = '<span style="background-color: #ADD8E6;">'+dstMatch+'</span>';
                            expl_text = expl_text.replace(dstMatch, dstReplacement);
                          }

                          explainText = expl_text;
                        }
                        else {
                          explainText = "Did not find entry of "+src+" and "+dst;
                        }
                        explainText += '\n' + reselectSrcText
                      }
                      selectionBox.innerHTML = filterText + textSeparator + explainText
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
                  const explanation = jsObject[clickedId].explanation;
                  filterText = ''
                  explanation.forEach((el, index) => {
                    filterText += el + '\n'
                  });
                  filterText += unfilterExplainText
                  selectionBox.innerHTML = filterText + textSeparator + explainText
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
                          filterText = mainTitleText + '\n'
                          filterText += filterExplainText
                          selectionBox.innerHTML = filterText + textSeparator + explainText
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
